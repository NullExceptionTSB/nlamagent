#include <Windows.h>

#include <json-c/json.h>

#include <packet.h>
// FUCKING MIDL
IID const IID_IADsUser = 
{ 0x3E37E320, 0x17E2, 0x11CF, 0xAB, 0xC4, 0x02, 0x60, 0x8C, 0x9E, 0x75, 0x53 };

VOID PktiChangePasswdSpecData(NLPACKET* pkt) {
    
}

VOID PktiDelUserSpecData(NLPACKET* pkt) {

}

VOID PktiAddUserSpecData(NLPACKET* pkt) {

}

VOID PktiFillSpecData(NLPACKET* pkt) {
    switch (pkt->opCode) {
        case OP_NOOP: return;
        case OP_ADD_USER: return PktiAddUserSpecData(pkt);
        case OP_DEL_USER: return PktiDelUserSpecData(pkt);
        case OP_CHANGE_PASSWD: return PktiChangePasswdSpecData(pkt);
        default:
            SetLastError(NLAM_PKT_INVALID_OPCODE);
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
        printf("JSONTOK: %s\n", json_tokener_error_desc(json_tokener_get_error(tokener)));
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
    else if (!strcmp(opcode_str, "DEL_USER"))
        pkt->opCode = OP_DEL_USER;
    else if (!strcmp(opcode_str, "NOOP")) 
        pkt->opCode = OP_NOOP;
    else {
        SetLastError(NLAM_PKT_INVALID_OPCODE);
        goto fail;
    }
    
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