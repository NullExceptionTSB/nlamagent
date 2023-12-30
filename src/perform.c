#include <Windows.h>

#include <wchar.h>

#include <iads.h>
#include <adshlp.h>
#include <packet.h>

LPWSTR iPerformAstrToWstr(LPSTR str) {
    int len = strlen(str);
    LPWSTR wstr = calloc(strlen(str)+1, sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, str, len+1, wstr, len+1);
    return wstr;
}

LPWSTR iPerformAssemblePath(LPSTR qn) {
    const INT winntlen = 8;
    INT ntplen = strlen(qn);

    LPWSTR lpRet = calloc(winntlen+ntplen+1, sizeof(WCHAR));
    if (!lpRet) 
        return NULL;
    memcpy(lpRet, L"WinNT://", winntlen*sizeof(WCHAR));

    MultiByteToWideChar(
        CP_ACP, MB_PRECOMPOSED, 
        qn, ntplen, lpRet+winntlen, ntplen+1
    );

    return lpRet;
}

HRESULT iPerformAddUser(NLPACKET* pkt) {

}

//! perform function for OP_DEL_USER
HRESULT iPerformDelUser(NLPACKET* pkt) {
    HRESULT hr = 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;
    NLP_DELUSER* i = pkt->specData;

    LPWSTR lpPath = iPerformAssemblePath(i->user_qn);
    if (!lpPath) goto fail;

    LPSTR lpszDomain = malloc(strlen(i->user_qn)+1);
    memcpy(lpszDomain, i->user_qn, strlen(i->user_qn)+1);

    //behold: you can't delete the an object using a method on the object
    //you have to use a method on the container holding it
    //you also can't get the container using a method on the child object
    //hence, you see this
    char* slash = strchr(lpszDomain, '/');
    if (!slash) {
        hr = E_FAIL;
        goto fail;
    }
    *slash = '\0';
    puts(lpszDomain);

    LPWSTR lpDomain = iPerformAssemblePath(lpszDomain);
    LPWSTR lpName = iPerformAstrToWstr(slash+1);
    IEnumVARIANT* varenum = NULL;

    IADsDomain* domain = NULL;
    hr = ADsGetObject(lpDomain, &IID_IADsDomain, &domain);
    if (hr != S_OK) 
        goto fail;

    IADs* obj = NULL;
    VARIANT* a;
    while (varenum->lpVtbl->Next(varenum, 1, &obj, NULL) == S_OK) {
        if (!obj) continue;
        BSTR b = NULL;
        obj->lpVtbl->get_Class(obj, &b);
        wprintf("%ls\n", b);
    }


    BSTR name = SysAllocString(lpName);

    //hr = domain->lpVtbl->Delete(domain, NULL, name);

    fail:
    if (lpszDomain)
        free(lpszDomain);
    if (lpDomain)
        free(lpDomain);
    if (lpPath)
        free(lpPath);
        /*
    if (usr)
        usr->lpVtbl->Release(usr);
*/
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
        (pkt->opCode == OP_CHANGE_PASSWD) ? i2->user_qn : i->user_qn;

    LPWSTR lpPath = iPerformAssemblePath(lpszUserQn);
    if (!lpPath) 
        return 0x80070000 | ERROR_NOT_ENOUGH_MEMORY;

    IADsUser* usr = NULL;
    hr = ADsGetObject(lpPath, &IID_IADsUser, &usr);

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
        case OP_SET_PASSWD: return iPerformChangePasswd(pkt);
        case OP_CHANGE_PASSWD: return iPerformChangePasswd(pkt);
        default: return ERROR_INVALID_PARAMETER;
    }
}
