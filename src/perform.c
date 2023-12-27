#include <Windows.h>
#include <iads.h>
#include <adshlp.h>
#include <packet.h>

LPWSTR iPerformAstrToWstr(LPSTR str) {
    int len = strlen(str);
    LPWSTR wstr = calloc(strlen(str)+1, sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, str, len+1, wstr, len+1);
    return wstr;
}

HRESULT iPerformAddUser(NLPACKET* pkt) {

}

HRESULT iPerformDelUser(NLPACKET* pkt) {

}

HRESULT iPerformChangePasswd(NLPACKET* pkt) {
    //i hate COM :-[
    NLP_CHPASSWD* i = pkt->specData;
    INT winntln = strlen("WinNT://");
    INT ntplen = strlen(i->user_ntpath);
    LPWSTR lpPath = calloc(winntln+ntplen+1, sizeof(WCHAR));

    MultiByteToWideChar(
        CP_ACP, MB_PRECOMPOSED, 
        i->user_ntpath, ntplen+1, lpPath+winntln, winntln+ntplen+1
    );

    IADsUser* usr = NULL;

    HRESULT hr = ADsGetObject(lpPath, &IID_IADsUser, &usr);
    free(lpPath);

    if (hr != S_OK) {
        if (usr)
            usr->lpVtbl->Release(usr);
        return hr;
    }

    LPWSTR lpNewPass = iPerformAstrToWstr(i->new_passwd);

    BSTR* bstrNewPass = SysAllocString(lpNewPass);
    hr = usr->lpVtbl->SetPassword(usr, bstrNewPass);
    SysFreeString(bstrNewPass);
    free(lpNewPass);
    usr->lpVtbl->Release(usr);
    
    return hr;
}

HRESULT PerformPacket(NLPACKET* pkt) {
    switch (pkt->opCode) {
        case OP_NOOP: return ERROR_SUCCESS;
        case OP_ADD_USER: return iPerformAddUser(pkt);
        case OP_DEL_USER: return iPerformDelUser(pkt);
        case OP_CHANGE_PASSWD: return iPerformChangePasswd(pkt);
        default: return ERROR_INVALID_PARAMETER;
    }
}
