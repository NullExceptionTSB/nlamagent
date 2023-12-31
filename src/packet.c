#include <Windows.h>

#include <stdio.h>

#include <json-c/json.h>

#include <packet.h>

VOID iPktSetPasswdSpecData(NLPACKET* pkt) {
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

VOID iPktChangePasswdSpecData(NLPACKET* pkt) {
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

VOID iPktDelUserSpecData(NLPACKET* pkt) {
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

VOID iPktAddUserSpecData(NLPACKET* pkt) {
    NLP_ADDUSER* spec = malloc(sizeof(NLP_ADDUSER));
    pkt->specData = spec;
    spec->property_count = 0;

    struct json_object* pathdn_obj =
        json_object_object_get(pkt->pktBase, "PathDN");
    struct json_object* usersam_obj =
        json_object_object_get(pkt->pktBase, "UserSAM");
    struct json_object* usercn_obj =
        json_object_object_get(pkt->pktBase, "UserCN");
    struct json_object* passwd_obj =
        json_object_object_get(pkt->pktBase, "Passwd");
    
    struct json_object* properties_obj =
        json_object_object_get(pkt->pktBase, "Properties");

    if (!pathdn_obj || !usersam_obj || !usercn_obj || !passwd_obj) {
        SetLastError(NLAM_PKT_MANDATORY_FIELD_NOT_SPECIFIED);
        return;
    }
    
    if (json_object_get_type(pathdn_obj) != json_type_string
     || json_object_get_type(usersam_obj) != json_type_string
     || json_object_get_type(usercn_obj) != json_type_string
     || json_object_get_type(passwd_obj) != json_type_string) {
        SetLastError(NLAM_PKT_INVALID_FIELD_TYPE);
        return;
     }

    spec->path_dn = json_object_get_string(pathdn_obj);
    spec->user_sam = json_object_get_string(usersam_obj);
    spec->user_cn = json_object_get_string(usercn_obj);
    spec->user_passwd = json_object_get_string(passwd_obj);

    if (!properties_obj || 
        (json_object_get_type(properties_obj) != json_type_object)) 
        spec->property_count = 0;
    else { 
        size_t ammt = 0;
        //this is library truly is something else
        //at LEAST add the bloody "is eof" API as an abstraction of this
        struct json_object_iterator iter = 
            json_object_iter_begin(properties_obj);
        struct json_object_iterator enditer = 
            json_object_iter_end(properties_obj);
        //pretty inefficient but acceptable considering lack of
        //a "count" api
        
        while (!json_object_iter_equal(&iter, &enditer)) {
            ammt++;
            json_object_iter_next(&iter);
        }
        
        iter = json_object_iter_begin(properties_obj);

        spec->property_count = ammt;
        spec->properties = calloc(ammt, sizeof(NL_PROPERTY));
        for (int i = 0; i < ammt; i++) {
            json_object* obj = json_object_iter_peek_value(&iter);
            int type = json_object_get_type(obj);
            switch (type) {
                case json_type_int:
                    spec->properties[i].type = NLPROP_INT;
                    spec->properties[i].value = malloc(sizeof(int));
                    *((int*)spec->properties[i].value) =
                        json_object_get_int(obj);
                    
                    break;
                case json_type_boolean:
                    spec->properties[i].type = NLPROP_BOOLEAN;
                    spec->properties[i].value = malloc(sizeof(int));
                    *((int*)spec->properties[i].value) =
                        json_object_get_boolean(obj);
                    break;
                case json_type_string:
                    spec->properties[i].type = NLPROP_STR;
                    size_t strcb = json_object_get_string_len(obj)+1;
                    spec->properties[i].value = 
                        malloc(strcb);
                    memcpy(spec->properties[i].value, 
                        json_object_get_string(obj),strcb);
                    break;
                default:
                    spec->properties[i].type = NLPROP_NULL;
                    break;
            }
            spec->properties[i].name = json_object_iter_peek_name(&iter);
            json_object_iter_next(&iter);
        }
    }
    SetLastError(ERROR_SUCCESS);
}

VOID iPktFillSpecData(NLPACKET* pkt) {
    switch (pkt->opCode) {
        case OP_NOOP: return;
        case OP_ADD_USER: return iPktAddUserSpecData(pkt);
        case OP_DEL_USER: return iPktDelUserSpecData(pkt);
        case OP_SET_PASSWD: return iPktSetPasswdSpecData(pkt);
        case OP_CHANGE_PASSWD: return iPktChangePasswdSpecData(pkt);
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
        SetLastError(NLAM_PKT_INVALID_OPCODE);
        goto fail;
    }
    
    SetLastError(0);
    iPktFillSpecData(pkt);
    if (GetLastError())
        goto fail;

    return pkt;
    

    fail:
    if (tokener)
        json_tokener_free(tokener);
    if (pkt)
        PktFree(pkt);
    return NULL;
}

/**
 * @brief Frees a NLPACKET object crteated by PktParse()
 * 
 * @param pkt Pointer to the NLPACKET object to be freed
 * @return NLPACKET* NULL
 */
NLPACKET* PktFree(NLPACKET* pkt) {
    if (pkt->opCode == OP_ADD_USER) {
        NLP_ADDUSER* sd = pkt->specData;
        
        for (size_t i = 0; i < sd->property_count; i++) 
            if (sd->properties[i].type != NLPROP_NULL)
                free(sd->properties[i].value);
        free(sd->properties);
    }
    if (pkt->pktBase) 
        json_object_put(pkt);
    if (pkt->specData)
        free(pkt->specData);
    free(pkt);
    return NULL;
}