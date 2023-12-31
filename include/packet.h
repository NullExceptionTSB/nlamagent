#pragma once
#include <Windows.h>

#include <json-c/json.h>

typedef enum _NLAMAGENT_PKT_OPCODE {
    OP_NOOP,
    OP_ADD_USER,
    OP_SET_PASSWD,
    OP_CHANGE_PASSWD,
    OP_DEL_USER
} PKTOPCODE;

typedef struct _NLAMAGENT_PACKET {
    PKTOPCODE opCode;
    json_object* pktBase;
    /**
     * @brief Pointer to operation-specific data
     * 
     * @details The data type to which this pointer points to depends on the
     *          opCode member.<br>
     *          OP_NOOP => Should be a NULL pointer. Ignored.
     *          OP_ADD_USER => Must point to a vaild NLP_ADDUSER struct.
     *          OP_CHANGE_PASSWD => Must point to a vaild NLP_CHPASSWD struct.
     *          OP_DEL_USER => Must point to a vaild NLP_DELUSER struct.
     */
    void* specData;
} NLPACKET;

typedef struct _NLAMAGENT_PKT_ADDUSER {
    char* resvd;
} NLP_ADDUSER;

/**
 * @brief Extended parameters for an OP_SET_PASSWD packet
 * \note All fields in this structure are mandatory
 */
typedef struct _NLAMAGENT_PKT_SETPASSWD {
    //! The AD DN of the target user
    char* user_dn;
    //! The new password
    char* new_passwd;
} NLP_SETPASSWD;

/**
 * @brief Extended parameters for an OP_CHANGE_PASSWD packet
 * \note All fields in this structure are mandatory
 */
typedef struct _NLAMAGENT_PKT_CHANGEPASSWD {
    //! The AD QN of the target user
    char* user_dn;
    //! The old password
    char* old_passwd;
    //! The new password
    char* new_passwd;
} NLP_CHANGEPASSWD;

/**
 * @brief Extended parameters for an OP_DEL_USER packet
 * \note All fields in this structure are mandatory
 */
typedef struct _NLAMAGENT_PKT_DELUSER {
    //! The AD QN of the target user
    char* user_dn;
} NLP_DELUSER;

typedef enum _NLAMAGENT_PKT_PARSE_ERROR {
    NLAM_PKT_INVALID_OPCODE = 0xA5000000,
    NLAM_PKT_INVALID_FIELD_TYPE,
    NLAM_PKT_MANDATORY_FIELD_NOT_SPECIFIED,
    NLAM_PKT_NOT_IMPLEMENTED
} NLAMAGENT_LASTERROR;

NLPACKET* PktParse(char* packet, int pkt_size);
NLPACKET* PktFree(NLPACKET* pkt);