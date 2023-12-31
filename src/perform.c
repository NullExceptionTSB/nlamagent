#include <Windows.h>

#include <wchar.h>

#include <iads.h>
#include <adshlp.h>
#include <packet.h>

//note that toggling this macro will break absolutely everything
#define ADSI_LDAP_PROVIDER

#ifdef ADSI_LDAP_PROVIDER
#define ADSI_PREFIX     L"LDAP://"
#else
#define ADSI_PREFIX     L"WinNT://"
#endif
#define ADSI_PREFLN     ((sizeof(ADSI_PREFIX)/sizeof((ADSI_PREFIX)[0]))-1)

LPWSTR iPerformAstrToWstr(LPSTR str) {
    int len = strlen(str);
    LPWSTR wstr = calloc(strlen(str)+1, sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, str, len+1, wstr, len+1);
    return wstr;
}

LPWSTR iPerformAssemblePath(LPSTR obj) {
    INT pathlen = strlen(obj);

    LPWSTR lpRet = calloc(ADSI_PREFLN+pathlen+1, sizeof(WCHAR));
    if (!lpRet) 
        return NULL;
    
    swprintf(lpRet, ADSI_PREFLN+pathlen+1, ADSI_PREFIX L"%s", obj);
    
    return lpRet;
}

HRESULT iPerformAssignProperty(NL_PROPERTY* prop, IADsUser* usr) {
    if (prop->type == NLPROP_NULL) 
        return S_OK;

    VARIANT var;

    HRESULT hrRet = S_OK;

    BSTR bstrName = NULL;
    BSTR bstrVal = NULL;

    LPWSTR lpStrval = NULL;

    LPWSTR lpName = iPerformAstrToWstr(prop->name);
    if (!lpName)
        return 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
    bstrName = SysAllocString(lpName);
    if (!bstrName) {
        hrRet = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
        goto fail;
    }

    VariantInit(&var);
    printf("adding property: %s (type %u)\n", prop->name, prop->type);

    switch (prop->type) {
        case NLPROP_BOOLEAN:
            printf("type: boolean, val %s\n", *((int*)(prop->value)) ? "true" : "false");
            V_BOOL(&var) = *((int*)(prop->value));
            V_VT(&var) = VT_BOOL;
            break;
        case NLPROP_INT:
            printf("type: int, val %i\n", *((int*)(prop->value)));
            V_I4(&var) = *((int*)(prop->value));
            V_VT(&var) = VT_I4;
            break;
        case NLPROP_STR:
            
            lpStrval = iPerformAstrToWstr(prop->value);
            wprintf(L"type: str, val %ls\n", lpStrval);
            if (!lpStrval) {
                hrRet = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
                goto fail;
            }

            bstrVal = SysAllocString(lpStrval);
            if (!bstrVal) {
                hrRet = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
                goto fail;
            }

            V_BSTR(&var) = bstrVal;
            V_VT(&var) = VT_BSTR;
            break;
        default:
            //should not happen :-]
            return E_FAIL;
    }

    hrRet = usr->lpVtbl->Put(usr, bstrName, var);

    fail:
    if (lpName) 
        free(lpName);
    if (lpStrval)
        free(lpStrval);
    if (bstrName) 
        SysFreeString(bstrName);
    if (bstrVal)
        SysFreeString(bstrVal);
    return hrRet;
}

HRESULT iPerformAddUser(NLPACKET* pkt) {
    HRESULT hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
    NLP_ADDUSER* i = pkt->specData;

    puts(i->path_dn);
    LPWSTR lpPath = iPerformAssemblePath(i->path_dn);

    IADsContainer* cont = NULL;
    IDispatch* dispatch = NULL;
    IADsUser* usr = NULL;

    if (!lpPath)
        goto fail;

    size_t szName = 3+strlen(i->user_cn)+1;
    LPWSTR lpName = calloc(szName, sizeof(WCHAR));
    if (!lpName) 
        goto fail;

    swprintf(lpName, szName, L"CN=%s", i->user_cn);    
    //converting astring parameters to wstring
    LPWSTR lpSamName = iPerformAstrToWstr(i->user_sam);
    if (!lpSamName)
        goto fail;

    LPWSTR lpPassword = iPerformAstrToWstr(i->user_passwd);
    if (!lpPassword)
        goto fail;

    //initialize bstrings
    BSTR bstrClass = SysAllocString(L"user");
    if (!bstrClass)
        goto fail;

    BSTR bstrName = SysAllocString(lpName);
    if (!bstrName)
        goto fail;
    
    BSTR bstrSamName = SysAllocString(lpSamName);
    if (!bstrSamName)
        goto fail;

    BSTR bstrSamProp = SysAllocString(L"sAMAccountName");
    if (!bstrSamProp)
        goto fail;
    
    BSTR bstrPasswd = SysAllocString(lpPassword);
    if (!bstrPasswd)
        goto fail;
    puts("a");
    //
    //ADSI operations
    //
    //open target container

    hr = ADsGetObject(lpPath, &IID_IADsContainer, &cont);

    wprintf(L"cont = %p, hresult = 0x%08X, path = %ls\n", cont, hr, lpPath);
    if (hr != S_OK)
        goto fail;
    
    //create user
    
    hr = cont->lpVtbl->Create(cont, bstrClass, bstrName, &dispatch);
    if (hr != S_OK)
        goto fail;
    
    //open user interface
    
    hr = dispatch->lpVtbl->QueryInterface(dispatch, &IID_IADsUser, &usr);
    if (hr != S_OK)
        goto fail;
    
    //set SAM name
    VARIANT var;
    VariantInit(&var);
    V_BSTR(&var) = bstrSamName;
    V_VT(&var) = VT_BSTR;
    
    hr = usr->lpVtbl->Put(usr, bstrSamProp, var);
    if (hr != S_OK)
        goto fail;
    
    //commit user
    hr = usr->lpVtbl->SetInfo(usr);

    //set the rest of parameters
    for (size_t j = 0; j < i->property_count; j++) {
        hr = iPerformAssignProperty(&(i->properties[j]), usr);
        if (hr != S_OK) {
            puts("it failed");
            goto fail;   
        }
    }

    //set password
    hr = usr->lpVtbl->SetPassword(usr, bstrPasswd);
    if (hr != S_OK)
        goto fail;

    //commit user (again)
    hr = usr->lpVtbl->SetInfo(usr);
    fail:

    if (lpPath)
        free(lpPath);
    if (lpName)
        free(lpName);
    if (lpSamName)
        free(lpSamName);
    if (lpPassword)
        free(lpPassword);

    if (bstrClass)
        SysFreeString(bstrClass);
    if (bstrName)
        SysFreeString(bstrName);
    if (bstrSamName)
        SysFreeString(bstrSamName);
    if (bstrSamProp)
        SysFreeString(bstrSamProp);
    if (bstrPasswd)
        SysFreeString(bstrPasswd);

    if (cont)
        cont->lpVtbl->Release(cont);
    if (dispatch)
        dispatch->lpVtbl->Release(dispatch);
    if (usr)
        usr->lpVtbl->Release(usr);
    return hr;
}

//! perform function for OP_DEL_USER
HRESULT iPerformDelUser(NLPACKET* pkt) {
    HRESULT hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
    NLP_DELUSER* i = pkt->specData;

    LPWSTR lpPath = iPerformAssemblePath(i->user_dn);
    if (!lpPath) 
        goto fail;

    IADsUser* usr = NULL;
    hr = ADsGetObject(lpPath, &IID_IADsUser, &usr);
    if (hr != S_OK) 
        goto fail;

    BSTR bstrParent = NULL;
    BSTR bstrName = NULL;
    hr = usr->lpVtbl->get_Parent(usr, &bstrParent);
    if (hr != S_OK)
        goto fail;
    hr = usr->lpVtbl->get_Name(usr, &bstrName);
    if (hr != S_OK)
        goto fail;

    IADsContainer* cont = NULL;
    hr = ADsGetObject(bstrParent, &IID_IADsContainer, &cont);
    if (hr != S_OK)
        goto fail;

    hr = cont->lpVtbl->Delete(cont, NULL, bstrName);
    
    fail:
    if (lpPath)
        free(lpPath);
    if (bstrParent)
        SysFreeString(bstrParent);
    if (bstrName)
        SysFreeString(bstrName);
        
    if (usr)
        usr->lpVtbl->Release(usr);
    if (cont)
        cont->lpVtbl->Release(cont);

    return hr;
}

//! grouped perform function for both OP_CHANGE_PASSWD and OP_SET_PASSWD ops
HRESULT iPerformChangePasswd(NLPACKET* pkt) {
    //i hate COM :-[
    HRESULT hr = 0x0;
    NLP_CHANGEPASSWD* i2 = pkt->specData;
    NLP_SETPASSWD* i = pkt->specData;

    LPSTR lpszNewPassword = 
        (pkt->opCode == OP_CHANGE_PASSWD) ? i2->new_passwd : i->new_passwd;
    LPSTR lpszUserQn = 
        (pkt->opCode == OP_CHANGE_PASSWD) ? i2->user_dn : i->user_dn;

    LPWSTR lpPath = iPerformAssemblePath(lpszUserQn);
    if (!lpPath) 
        return 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;

    BSTR debug = NULL;
    IADsUser* usr = NULL;
    hr = ADsGetObject(lpPath, &IID_IADsUser, &usr);
    usr->lpVtbl->get_Name(usr, &debug);

    if (hr != S_OK) 
        goto fail;

    LPWSTR lpOldPass = NULL;
    LPWSTR lpNewPass = iPerformAstrToWstr(lpszNewPassword);
    if (!lpNewPass) {
        hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
        goto fail;
    }

    BSTR* bstrOldPass = NULL;
    BSTR* bstrNewPass = SysAllocString(lpNewPass);
    if (!bstrNewPass) {
        hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
        goto fail;
    }

    // avoiding redundant code by doing this
    if (pkt->opCode == OP_CHANGE_PASSWD) {
        hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
        lpOldPass = iPerformAstrToWstr(i2->old_passwd);

        if (!lpOldPass) goto fail;
        
        bstrOldPass = SysAllocString(lpOldPass);
        if (!bstrOldPass) goto fail;

        hr = usr->lpVtbl->ChangePassword(usr, bstrOldPass, bstrNewPass);
    } else 
        hr = usr->lpVtbl->SetPassword(usr, bstrNewPass);

    VARIANT var;
    VariantInit(&var);
    usr->lpVtbl->Get(usr, SysAllocString(L"userAccountControl"), &var);

    printf("ExtreDebug: %u (%u)\n", V_VT(&var), V_INT(&var));

    fail:
    if (usr)
        usr->lpVtbl->Release(usr);
    if (lpPath)
        free(lpPath);
    if (lpOldPass)
        free(lpOldPass);
    if (lpNewPass)
        free(lpNewPass);
    if (bstrOldPass)
        SysFreeString(bstrOldPass);
    if (bstrNewPass)
        SysFreeString(bstrNewPass);
    return hr;
}

HRESULT PerformPacket(NLPACKET* pkt) {
    switch (pkt->opCode) {
        case OP_NOOP: return ERROR_SUCCESS;
        case OP_ADD_USER: return iPerformAddUser(pkt);
        case OP_DEL_USER: return iPerformDelUser(pkt);
        //gangster move
        case OP_SET_PASSWD:
        case OP_CHANGE_PASSWD: return iPerformChangePasswd(pkt);
        default: return ERROR_INVALID_PARAMETER;
    }
}
