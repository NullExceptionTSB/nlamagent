#include <Windows.h>

#include <stdio.h>

#include <json-c/json.h>

#include <packet.h>

VOID PktiSetPasswdSpecData(NLPACKET* pkt) {
    NLP_SETPASSWD* spec = malloc(sizeof(NLP_SETPASSWD));
    pkt->specData = spec;

    struct json_object* dn_obj = 
        json_object_object_get(pkt->pktBase, "DN");
    struct json_object* passwd_obj =
        json_object_object_get(pkt->pktBase, "NewPassword");
    
    if (!dn_obj || !passwd_obj) {
        SetLastError(NLAM_PKT_MANDATORY_FIELD_NOT_SPECIFIED);
        return;
    }

    if (json_object_get_type(dn_obj) != json_type_string
     || json_object_get_type(passwd_obj) != json_type_string) {
        SetLastError(NLAM_PKT_INVALID_FIELD_TYPE);
        return;
    }

    spec->user_dn = json_object_get_string(dn_obj);
    spec->new_passwd = json_object_get_string(passwd_obj);

    SetLastError(ERROR_SUCCESS);
}

VOID PktiChangePasswdSpecData(NLPACKET* pkt) {
    NLP_CHANGEPASSWD* spec = malloc(sizeof(NLP_CHANGEPASSWD));
    pkt->specData = spec;

    struct json_object* dn_obj = 
        json_object_object_get(pkt->pktBase, "DN");
    struct json_object* opasswd_obj =
        json_object_object_get(pkt->pktBase, "OldPassword");
    struct json_object* passwd_obj =
        json_object_object_get(pkt->pktBase, "NewPassword");
    
    if (!opasswd_obj || !dn_obj || !passwd_obj) {
        SetLastError(NLAM_PKT_MANDATORY_FIELD_NOT_SPECIFIED);
        return;
    }

    if (json_object_get_type(dn_obj) != json_type_string
     || json_object_get_type(passwd_obj) != json_type_string
     || json_object_get_type(opasswd_obj) != json_type_string) {
        SetLastError(NLAM_PKT_INVALID_FIELD_TYPE);
        return;
    }

    spec->user_dn = json_object_get_string(dn_obj);
    spec->new_passwd = json_object_get_string(passwd_obj);
    spec->old_passwd = json_object_get_string(opasswd_obj);

    SetLastError(ERROR_SUCCESS);
}

VOID PktiDelUserSpecData(NLPACKET* pkt) {
    NLP_DELUSER* spec = malloc(sizeof(NLP_DELUSER));
    pkt->specData = spec;

    struct json_object* dn_obj =
        json_object_object_get(pkt->pktBase, "DN");

    if (!dn_obj) {
        SetLastError(NLAM_PKT_MANDATORY_FIELD_NOT_SPECIFIED);
        return;
    }

    if (json_object_get_type(dn_obj) != json_type_string) {
        SetLastError(NLAM_PKT_INVALID_FIELD_TYPE);
        return;
    }

    spec->user_dn = json_object_get_string(dn_obj);

    SetLastError(ERROR_SUCCESS);
}

VOID PktiAddUserSpecData(NLPACKET* pkt) {
    
}

VOID PktiFillSpecData(NLPACKET* pkt) {
    switch (pkt->opCode) {
        case OP_NOOP: return;
        case OP_ADD_USER: return PktiAddUserSpecData(pkt);
        case OP_DEL_USER: return PktiDelUserSpecData(pkt);
        case OP_SET_PASSWD: return PktiSetPasswdSpecData(pkt);
        case OP_CHANGE_PASSWD: return PktiChangePasswdSpecData(pkt);
        default:
            SetLastError(NLAM_PKT_NOT_IMPLEMENTED);
    }
}

/**
 * @brief Parses a packet received from the client to usable form
 * 
 * 
 * @param packet The character buffer of the packet
 * @param pkt_size The size of the packet buffer.
 * @return NLPACKET* NULL if parsing failed (invalid packet, ...)
 *                   Pointer to an NLPACKET structure if parsing succeeded
 * 
 * @note uses LastError for reporting tokenizer errors<br>
 *       Tokenizer errors are ORed with 0xA0000000 to differentiate them
 *       from WinAPI lasterror values.<br>
 *       If the errors come from invalid packet structure and not json errors, 
 *       the error is also ORed with with 0x05000000.
 * @note The returned packet <b>must</b> be freed with PktFree() when it is no
 *       longer needed.
 */
NLPACKET* PktParse(char* packet, int pkt_size) {
    int pktsz = strnlen(packet, pkt_size);

    NLPACKET* pkt = malloc(sizeof(NLPACKET));
    json_tokener* tokener = json_tokener_new();
    if (!pkt || !tokener) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    pkt->pktBase = json_tokener_parse_ex(tokener, packet, pktsz);
    pkt->specData = NULL;
    
    if (!pkt->pktBase) {
        SetLastError(json_tokener_get_error(tokener) | 0xA0000000);
        printf("JSONTOK: %s\n", 
            json_tokener_error_desc(json_tokener_get_error(tokener)));
        goto fail;
    }

    struct json_object* opcode_obj = 
        json_object_object_get(pkt->pktBase, "Opcode");  

    if ((!opcode_obj) || 
        (json_object_get_type(opcode_obj) != json_type_string)) {
        puts("JSONTOK: Type validation failed");
        printf("opcode_obj %p\n", opcode_obj);
        SetLastError(NLAM_PKT_INVALID_OPCODE);
        goto fail;
    }

    char* opcode_str = json_object_get_string(opcode_obj);

    if (!strcmp(opcode_str, "ADD_USER")) 
        pkt->opCode = OP_ADD_USER;
    else if (!strcmp(opcode_str, "CHANGE_PASSWD")) 
        pkt->opCode = OP_CHANGE_PASSWD;
    else if (!strcmp(opcode_str, "SET_PASSWD")) 
        pkt->opCode = OP_SET_PASSWD;
    else if (!strcmp(opcode_str, "DEL_USER"))
        pkt->opCode = OP_DEL_USER;
    else if (!strcmp(opcode_str, "NOOP")) 
        pkt->opCode = OP_NOOP;
    else {
        printf("JSONTOK: Unknown opcode %s\n", opcode_str);
        SetLastError(NLAM_PKT_INVALID_OPCODE);
        goto fail;
    }

    printf("JSONTOK: openum %u\n", pkt->opCode);
    
    SetLastError(0);
    PktiFillSpecData(pkt);
    if (GetLastError())
        goto fail;
    return pkt;
    

    fail:
    if (tokener)
        json_tokener_free(tokener);
    if (pkt)
        free(pkt);
    return NULL;
}

/**
 * @brief Frees a NLPACKET object crteated by PktParse()
 * 
 * @param pkt Pointer to the NLPACKET object to be freed
 * @return NLPACKET* NULL
 */
NLPACKET* PktFree(NLPACKET* pkt) {
    if (pkt->pktBase) 
        json_object_put(pkt);
    if (pkt->specData)
        free(pkt->specData);
    free(pkt);
    return NULL;
}