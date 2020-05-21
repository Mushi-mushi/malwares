  /*

Authors: Henri Ranki <ranki@ssh.fi>

Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Defines functions inserting audit entries in a log file. Defines also different events which
may be audited.

*/

#ifndef SSHAUDIT_H
#define SSHAUDIT_H

#include "sshbuffer.h"

/***********************************************************************
 * Types
 ***********************************************************************/

/* 
 * List of auditable events. These identify the event which is being 
 * audited. 
 */
typedef enum {
  /* The following events are for IPsec engine*/
  /* If a packet offered to AH for processing appears to be an IP 
     fragment. The audit log entry for this event SHOULD include 
     the SPI value, date/time, Source Address, Destination Address, 
     and (in IPv6) the Flow ID. */
  SSH_AUDIT_AH_IP_FRAGMENT,

  /* When mapping the IP datagram to the appropriate SA, the SA
     lookup fails. The audit log entry for this event SHOULD include 
     the SPI value, date/time, Source Address, Destination Address, 
     and (in IPv6) the cleartext Flow ID. */
  SSH_AUDIT_AH_SA_LOOKUP_FAILURE,

  /* If a received packet does not fall within the receivers sliding 
     window, the receiver MUST discard the received IP datagram as 
     invalid; The audit log entry for this event SHOULD include the 
     SPI value, date/time, Source Address, Destination Address, the 
     Sequence Number, and (in IPv6) the Flow ID.*/
  SSH_AUDIT_AH_SEQUENCE_NUMBER_FAILURE,

  /* If the computed and received ICV's do not match, then the receiver 
     MUST discard the received IP datagram as invalid.
     The audit log entry SHOULD include the SPI value, date/time 
     received, Source Address, Destination Address, and (in IPv6) 
     the Flow ID.*/
  SSH_AUDIT_AH_ICV_FAILURE,

  /* An attempt to transmit a packet that would result in Sequence Number 
     overflow if anti-replay is enabled. The audit log entry SHOULD include 
     the SPI value, date/time, Source Address, Destination Address, 
     and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_SEQUENCE_NUMBER_OVERFLOW,

  /* If a packet offered to ESP for processing appears to be an IP 
     fragment. The audit log entry for this event SHOULD include 
     the SPI value, date/time, Source Address, Destination Address, 
     and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_IP_FRAGMENT,

  /* When mapping the IP datagram to the appropriate SA, the SA
     lookup fails. The audit log entry for this event SHOULD include 
     the SPI value, date/time, Source Address, Destination Address,
     and (in IPv6) the cleartext Flow ID.*/
  SSH_AUDIT_ESP_SA_LOOKUP_FAILURE,

  /* If a received packet does not fall within the receivers sliding 
     window, the receiver MUST discard the received IP datagram as 
     invalid; The audit log entry for this event SHOULD include the 
     SPI value, date/time, Source Address, Destination Address, the 
     Sequence Number, and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_SEQUENCE_NUMBER_FAILURE,

  /* If the computed and received ICV's do not match, then the receiver 
     MUST discard the received IP datagram as invalid.
     The audit log entry SHOULD include the SPI value, date/time 
     received, Source Address, Destination Address, and (in IPv6) 
     the Flow ID.*/
  SSH_AUDIT_ESP_ICV_FAILURE,

  /* The following events are for ISAKMP*/
  /* The message retry limit is reached when transmitting ISAKMP 
     messages.*/
  SSH_AUDIT_IKE_RETRY_LIMIT_REACHED,

  /* When ISAKMP message is received and the cookie validation fails. */
  SSH_AUDIT_IKE_INVALID_COOKIE,

  /* If the Version field validation fails.*/ 
  SSH_AUDIT_IKE_INVALID_ISAKMP_VERSION,

  /* If the Exchange Type field validation fails. */
  SSH_AUDIT_IKE_INVALID_EXCHANGE_TYPE,

  /* If the Flags field validation fails.*/
  SSH_AUDIT_IKE_INVALID_FLAGS,

  /* If the Message ID validation fails. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_MESSAGE_ID,

  /* When any of the ISAKMP Payloads are received and if the NextPayload 
     field validation fails.*/
  SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,

  /* If the value in the RESERVED field is not zero.*/ 
  SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,

  /*  If the DOI determination fails.*/
  SSH_AUDIT_IKE_INVALID_DOI,

  /* If the Situation determination fails.*/ 
  SSH_AUDIT_IKE_INVALID_SITUATION,

  /* If the Security Association Proposal is not accepted.*/ 
  SSH_AUDIT_IKE_INVALID_PROPOSAL,

  /* If the SPI is invalid.*/ 
  SSH_AUDIT_IKE_INVALID_SPI,

  /*If the proposals are not formed correctly.*/
  SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX, 

  /* If the Transform-ID field is invalid. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_TRANSFORM,

  /* If the transforms are not formed correctly. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_ATTRIBUTES,

  /* If the Key Exchange determination fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_KEY_INFORMATION,

  /* If the Identification determination fails. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_ID_INFORMATION,

  /* If the Certificate Data is invalid or improperly formatted. (not used)*/
  SSH_AUDIT_IKE_INVALID_CERTIFICATE,

  /* If the Certificate Encoding is invalid. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_CERTIFICATE_TYPE,

  /* If the Certificate Encoding is not supported. (not used)*/ 
  SSH_AUDIT_IKE_CERTIFICATE_TYPE_UNSUPPORTED,

  /* If the Certificate Authority is invalid or improperly formatted. (not used)*/
  SSH_AUDIT_IKE_INVALID_CERTIFICATE_AUTHORITY,

  /* If a requested Certificate Type with the specified Certificate 
     Authority is not available. (not used)*/ 
  SSH_AUDIT_IKE_CERTIFICATE_UNAVAILABLE,

  /* If the Hash determination fails. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_HASH_INFORMATION,

  /* If the Hash function fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_HASH_VALUE,

  /* If the Signature determination fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_SIGNATURE_INFORMATION,

  /* If the Signature function fails. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_SIGNATURE_VALUE,

  /* When receivers notification payload check fails. (not used)*/ 
  SSH_AUDIT_IKE_NOTIFICATION_PAYLOAD_RECEIVED,

  /* If the Protocol-Id determination fails. */ 
  SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,

  /* If the Notify Message Type is invalid. (not used)*/ 
  SSH_AUDIT_IKE_INVALID_MESSAGE_TYPE,

  /* If receiver detects an error in Delete Payload. */ 
  SSH_AUDIT_IKE_DELETE_PAYLOAD_RECEIVED,

  /* If receiver detects an error in payload lengths.*/ 
  SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,

  SSH_AUDIT_MAX_VALUE,

  /* Marks the end of the variable list */
  SSH_AUDIT_EVENT_END
} SshAuditEvent;


/*
 * Enum types that are used when passing parameters to audit function. Audit
 * function takes a variable number of arguments. First is the type of the 
 * auditable event (SshAuditEvent). Following that is listed additional information 
 * which is inserted to the audit log too. Additional arguments starts with 
 * type specified here. After that is a couple of parameters depending on the 
 * type of argument. Needed parameters is commented here. List must always end 
 * with a SSH_AUDIT_ARGUMENT_END. 
 */
typedef enum {
  /* Contains the SPI for the packet which caused an auditable event, for IKE
     this is the initiator and responder cookies. If the length is zero then
     this value is ignored. */
  SSH_AUDIT_SPI,          /* unsigned char *, size_t */

  /* Contains the source address for the packet which caused the auditable
     event, for IKE this is local ip address. If the length is zero then this
     value is ignored.*/
  SSH_AUDIT_SOURCE_ADDRESS,   /* unsigned char *, size_t */

  /* Contains the destination address for the packet which caused the auditable
     event, for IKE this is remote ip address. If the length is zero then this
     value is ignored.*/
  SSH_AUDIT_DESTINATION_ADDRESS,   /* unsigned char *, size_t */

  /* Contains the source address for the packet which caused the auditable
     event, for IKE this is local ip address. If the pointer is NULL then this
     value is ignored. This contains the source address in text format. */
  SSH_AUDIT_SOURCE_ADDRESS_STR,   /* unsigned char * */

  /* Contains the destination address for the packet which caused the auditable
     event, for IKE this is remote ip address. If the pointer is NULL then this
     value is ignored. This contains the destination address in text format. */
  SSH_AUDIT_DESTINATION_ADDRESS_STR,   /* unsigned char * */

  /* Contains the Flow ID for the packet which caused the auditable event. This
     conserns only IPv6 addresses. If the length is zero then this value is
     ignored.*/
  SSH_AUDIT_IPV6_FLOW_ID,   /* unsigned char *, size_t */

  /* Contains the sequence number for the packet which caused the auditable
     event. If the length is zero then this value is ignored. */
  SSH_AUDIT_SEQUENCE_NUMBER,   /* unsigned char *, size_t */

  /* Describing text for the event. If the pointer is NULL then this value is
     ignored. */
  SSH_AUDIT_TXT,                /* unsigned char * */

  /* Marks end of the argument list. */
  SSH_AUDIT_ARGUMENT_END
} SshAuditArgument;


/*
 * A structure that is given to ssh_audit_init function as a parameter. 
 * If neither Windows system log or log_filename is defined ssh_log_event()
 * function is used as a default. It takes facility and severity as a 
 * parameter. 
 */
typedef struct SshAuditParamsRec {
#ifdef WIN32
  /* Name passed to the windows system log. If NULL not used. */
  unsigned char *win_syslog_source_name;    
#endif /* WIN32 */
  /* Specifies the file where events are recorded. If NULL not used. */
  unsigned char *log_filename; 
  /* Loging facility and severity. These are used only if default 
     log handler is used. */
  SshLogFacility facility; 
  SshLogSeverity severity;
} *SshAuditParams;

/*
 * Context structure which is initialized in ssh_audit_init-function.
 */
typedef struct SshAuditContextRec *SshAuditContext;

/*******************************************************************************
* Functions inserting entries into the audit log and controlling the insertion.
*******************************************************************************/
/* 
 * Initializes audit context. Calling function MUST remember to release memory
 * reserved for context structure. params contains parameters for initialized 
 * context. These are:
 * win_syslog_source_name - Name passed to windows system log may be NULL if not used.
 *                          In unix NOT defined
 * log_filename - Name for the file used to store audit events may be NULL if not used
 * use_stderr - TRUE or FALSE debending whether we want to use stderr to output events 
 *              or not
 * All above destinations can be used simultaneously.
 */
SshAuditContext ssh_audit_init(SshAuditParams params);

/* 
 * Inserts specified event into log file.
 * event parameter specifies the audited event. Each element after that must start with 
 * a SshAuditformat type, followed by arguments of the appropriate 
 * type, and the list must end with SSH_AUDIT_FORMAT_END. If context is NULL
 * then this call is ignored. 
 */
void ssh_audit_event(SshAuditContext context, SshAuditEvent event, ...);

/*
 * Disables or enables events listed from given context. State is either TRUE or FALSE.
 * After that is variable number argument list, which declares auditable events to be
 * allowed or disallowed. Variable list MUST end with SSH_AUDIT_EVENT_END.
 */
void ssh_audit_change_event_state(SshAuditContext context, Boolean state, ...);

#endif /* SSHAUDIT_H */



