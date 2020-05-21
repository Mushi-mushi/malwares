/*

Authors: Henri Ranki <ranki@ssh.fi>

Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Functions inserting audit entries into a log file. 
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshbuffer.h"
#include "stdarg.h"
#include "sshenum.h"
#include "sshaudit.h"
#ifdef WIN32
#include <windows.h>
#endif

/*
 * Context structure which is initialized in ssh_audit_init-function.
 */
struct SshAuditContextRec {
#ifdef WIN32
  const unsigned char *win_syslog_source_name;
#endif /* WIN32 */
  const unsigned char *log_filename;
  FILE *out_file; 
  /* Declares which events are allowed */
  Boolean ssh_audit_event_allowed[SSH_AUDIT_MAX_VALUE];
  /* Loging facility and severity. These are used only if default 
     log handler is used. */
  SshLogFacility facility; 
  SshLogSeverity severity;
};

/* 
 * Array that contains titles for the auditable events 
 */
const SshKeyword ssh_audit_event_title[] = {
 { "IKE_AH_IP_FRAGMENT", SSH_AUDIT_AH_IP_FRAGMENT },
 { "IKE_AH_SA_LOOKUP_FAILURE", SSH_AUDIT_AH_SA_LOOKUP_FAILURE },
 { "IKE_AH_SEQUENCE_NUMBER_FAILURE", SSH_AUDIT_AH_SEQUENCE_NUMBER_FAILURE },
 { "IKE_AH_ICV_FAILURE", SSH_AUDIT_AH_ICV_FAILURE },
 { "IKE_ESP_SEQUENCE_NUMBER_OVERFLOW", SSH_AUDIT_ESP_SEQUENCE_NUMBER_OVERFLOW },
 { "IKE_ESP_IP_FRAGMENT", SSH_AUDIT_ESP_IP_FRAGMENT },
 { "IKE_ESP_SA_LOOKUP_FAILURE", SSH_AUDIT_ESP_SA_LOOKUP_FAILURE },
 { "IKE_ESP_SEQUENCE_NUMBER_FAILURE", SSH_AUDIT_ESP_SEQUENCE_NUMBER_FAILURE },
 { "IKE_ESP_ICV_FAILURE", SSH_AUDIT_ESP_ICV_FAILURE },
 { "IKE_RETRY_LIMIT_REACHED", SSH_AUDIT_IKE_RETRY_LIMIT_REACHED },
 { "IKE_INVALID_COOKIE", SSH_AUDIT_IKE_INVALID_COOKIE },
 { "IKE_INVALID_ISAKMP_VERSION", SSH_AUDIT_IKE_INVALID_ISAKMP_VERSION },
 { "IKE_INVALID_EXCHANGE_TYPE", SSH_AUDIT_IKE_INVALID_EXCHANGE_TYPE },
 { "IKE_INVALID_FLAGS", SSH_AUDIT_IKE_INVALID_FLAGS },
 { "IKE_INVALID_MESSAGE_ID", SSH_AUDIT_IKE_INVALID_MESSAGE_ID },
 { "IKE_INVALID_NEXT_PAYLOAD", SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD },
 { "IKE_INVALID_RESERVED_FIELD", SSH_AUDIT_IKE_INVALID_RESERVED_FIELD },
 { "IKE_INVALID_DOI", SSH_AUDIT_IKE_INVALID_DOI },
 { "IKE_INVALID_SITUATION", SSH_AUDIT_IKE_INVALID_SITUATION },
 { "IKE_INVALID_PROPOSAL", SSH_AUDIT_IKE_INVALID_PROPOSAL },
 { "IKE_INVALID_SPI", SSH_AUDIT_IKE_INVALID_SPI },
 { "IKE_BAD_PROPOSAL_SYNTAX", SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX }, 
 { "IKE_INVALID_TRANSFORM", SSH_AUDIT_IKE_INVALID_TRANSFORM },
 { "IKE_INVALID_ATTRIBUTES", SSH_AUDIT_IKE_INVALID_ATTRIBUTES },
 { "IKE_INVALID_KEY_INFORMATION", SSH_AUDIT_IKE_INVALID_KEY_INFORMATION },
 { "IKE_INVALID_ID_INFORMATION", SSH_AUDIT_IKE_INVALID_ID_INFORMATION },
 { "IKE_INVALID_CERTIFICATE", SSH_AUDIT_IKE_INVALID_CERTIFICATE },
 { "IKE_INVALID_CERTIFICATE_TYPE", SSH_AUDIT_IKE_INVALID_CERTIFICATE_TYPE },
 { "IKE_CERTIFICATE_TYPE_UNSUPPORTED", SSH_AUDIT_IKE_CERTIFICATE_TYPE_UNSUPPORTED },
 { "IKE_INVALID_CERTIFICATE_AUTHORITY", SSH_AUDIT_IKE_INVALID_CERTIFICATE_AUTHORITY },
 { "IKE_CERTIFICATE_UNAVAILABLE", SSH_AUDIT_IKE_CERTIFICATE_UNAVAILABLE },
 { "IKE_INVALID_HASH_INFORMATION", SSH_AUDIT_IKE_INVALID_HASH_INFORMATION },
 { "IKE_INVALID_HASH_VALUE", SSH_AUDIT_IKE_INVALID_HASH_VALUE },
 { "IKE_INVALID_SIGNATURE_INFORMATION", SSH_AUDIT_IKE_INVALID_SIGNATURE_INFORMATION },
 { "IKE_INVALID_SIGNATURE_VALUE", SSH_AUDIT_IKE_INVALID_SIGNATURE_VALUE },
 { "IKE_NOTIFICATION_PAYLOAD_RECEIVED", SSH_AUDIT_IKE_NOTIFICATION_PAYLOAD_RECEIVED },
 { "IKE_INVALID_PROTOCOL_ID", SSH_AUDIT_IKE_INVALID_PROTOCOL_ID },
 { "IKE_INVALID_MESSAGE_TYPE", SSH_AUDIT_IKE_INVALID_MESSAGE_TYPE },
 { "IKE_DELETE_PAYLOAD_RECEIVED", SSH_AUDIT_IKE_DELETE_PAYLOAD_RECEIVED }, 
 { "IKE_UNEQUAL_PAYLOAD_LENGTHS", SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS }, 
 { NULL, 0 }
};


/*
 * Prints an IPv4 address to given buffer.
 */
char *ssh_audit_v4tostr(char *buf, size_t len, unsigned char *addr)
{
  snprintf(buf, len, "%d.%d.%d.%d",
           addr[3], addr[2], addr[1], addr[0]);
  return buf;
}

/*
 * Prints an IPv6 address to given buffer.
 */
char *ssh_audit_v6tostr(char *buf, size_t len, unsigned char *addr)
{
  char word_str[6];
  int i = 0, hop;

  buf[0] = 0;
  while (i < 16)
  {
    snprintf(word_str, 6, "%02x%02x", addr[i], addr[i+1]);
    if ((strlen(buf) + strlen(word_str)+1) < len)
    {
      /* Ignore zeroes from the beginning of the string */
      hop = 0;
      while ((word_str[hop] == '0') && (hop < (strlen(word_str)-1))) 
        hop++;
      strcat(buf, &word_str[hop]);
      if (i != 14) strcat(buf, ":");
    }
    i += 2;
  }
  return buf;
}

/* 
 * Converts binary numbers to string. s is pointer to character buffer that have to be
 * large enough to contain converted string. size is the amount of bytes to convert and buffer
 * is a pointer to the start of the buffer containing the binary data to be converted. 
 */
char *ssh_bin_to_hex_str(char *s, size_t size, unsigned char *buffer)
{
  int i = size-1;
  char byte_str[3];

  /* Skip leading zeroes */
  while ((i >= 0) && (buffer[i] == 0)) i--;

  s[0] = '\0';
  for (; i >= 0; i--)
  {
    snprintf(byte_str, 3, "%02x", buffer[i]);
    strcat(s, byte_str);
  }
  return s;
}

/* 
 * Formats string that is being writen to the log file. Function gets its 
 * information in variable-length argument list. Each element must start with 
 * a SshAuditformat type followed by arguments of the appropriate type. 
 * The list must end with SSH_AUDIT_ARGUMENT_END.  
 * Function returns buffer containing the constructed string. 
 * NOTE: Returned buffer MUST be released by the calling function! 
 */
SshBuffer *ssh_format_audit_string(va_list ap)
{
  SshAuditArgument format;
  char s[128];
  SshBuffer *result;
  SshUInt32 size;
  unsigned char *i;

  result = ssh_buffer_allocate();
  

  for (;;)
    {
      format = va_arg(ap, SshAuditArgument);
      switch (format)
        {
        case SSH_AUDIT_SPI:
            i = va_arg(ap, unsigned char *);
            size = va_arg(ap, size_t);
            if (i == NULL || size == 0)
              break;
            ssh_bin_to_hex_str(s, size, i);
            ssh_buffer_append_cstrs(result, "  SPI:0x", s, NULL);
          break;
          
        case SSH_AUDIT_SOURCE_ADDRESS:
            i = va_arg(ap, unsigned char *);
            size = va_arg(ap, size_t);
            if (i == NULL || size == 0)
              break;
            if (size == 4)
              ssh_audit_v4tostr(s, sizeof(s), i);
            else
              ssh_audit_v6tostr(s, sizeof(s), i);

            ssh_buffer_append_cstrs(result, "  Source addr:", s, NULL);
          break;

        case SSH_AUDIT_DESTINATION_ADDRESS:
            i = va_arg(ap, unsigned char *);
            size = va_arg(ap, size_t);
            if (i == NULL || size == 0)
              break;
            if (size == 4)
              ssh_audit_v4tostr(s, sizeof(s), i);
            else
              ssh_audit_v6tostr(s, sizeof(s), i);

            ssh_buffer_append_cstrs(result, "  Destination addr:", s, NULL);
          break;

        case SSH_AUDIT_SOURCE_ADDRESS_STR:
            i = va_arg(ap, unsigned char *);
            if (i == NULL)
              break;
            ssh_buffer_append_cstrs(result, "  Source addr:", i, NULL); 
            break;

        case SSH_AUDIT_DESTINATION_ADDRESS_STR:
            i = va_arg(ap, unsigned char *);
            if (i == NULL)
              break;
            ssh_buffer_append_cstrs(result, "  Destination addr:", i, NULL);
            break;

        case SSH_AUDIT_IPV6_FLOW_ID:
            i = va_arg(ap, unsigned char *);
            size = va_arg(ap, size_t);
            if (i == NULL || size == 0)
              break;
            ssh_bin_to_hex_str(s, size, i);
            ssh_buffer_append_cstrs(result, "  IPV6:0x", s, NULL); 
          break;

        case SSH_AUDIT_SEQUENCE_NUMBER:
            i = va_arg(ap, unsigned char *);
            size = va_arg(ap, size_t);
            if (i == NULL || size == 0)
              break;
            ssh_bin_to_hex_str(s, size, i);
            ssh_buffer_append_cstrs(result, "  Sequence NO:0x", s, NULL); 
          break;

        case SSH_AUDIT_TXT:
            i = va_arg(ap, unsigned char *);
            if (i == NULL)
              break;
            ssh_buffer_append_cstrs(result, "  Description:", i, NULL); 
            break;

        case SSH_AUDIT_ARGUMENT_END:
          return result;  /* return constructed string */

        default:
          ssh_fatal("ssh_format_audit_string: invalid format code %d (check arguments and SSH_AUDIT_ARGUMENT_END)", 
                    (int)format);
        }
    }
  /*NOTREACHED*/
}

/* 
 * Inserts an entry to specified audit log. msg contains the formatted 
 * string.
 */
void ssh_send_log_message(SshAuditContext context, unsigned char *msg)
{
#ifdef WIN32
  HANDLE hEventSource;
  LPTSTR  lpszStrings[1];
#endif /* WIN32 */

  /* If filename is specified insert log entry into given file.*/
  if (context->out_file) 
    fprintf(context->out_file, "%s\n", msg);
  /* Otherwise insert entry into Windows system log 
     if source_name is defined. */
#ifdef WIN32
  else if (context->win_syslog_source_name)
  {
    hEventSource = RegisterEventSource(NULL, 
                                       TEXT(context->win_syslog_source_name));
    if (hEventSource) 
    {
      lpszStrings[0] = msg;

      ReportEvent(hEventSource,         /* handle of event source */
                  EVENTLOG_ERROR_TYPE,  /* event type */
                  0,                    /* event category */
                  0,                    /* event ID */
                  NULL,                 /* current user's SID */
                  1,                    /* strings in lpszStrings */
                  0,                    /* no bytes of raw data */
                  lpszStrings,          /* array of error strings */
                  NULL);                /* no raw data */
      DeregisterEventSource(hEventSource);
    }
  }
#endif /* WIN32 */
  /* If nothing else is defined use default handler for logging.
     Message is sent to log callback if one defined */
  else
    ssh_log_event(context->facility, context->severity, "%s", msg);
}

/* 
 * Initializes audit context. Calling function MUST remember to release memory
 * reserved for context structure. params contains parameters for initialized 
 * context. These are:
 * win_syslog_source_name - Name passed to windows system log may be NULL if 
 *                          not used. In unix NOT defined
 * log_filename - Name for the file used to store audit events may be NULL 
 *                if not used
 * If neither Windows system log or log_filename is defined ssh_log_event()
 * function is used as a default. It takes facility and severity as a 
 * parameter. 
 */
SshAuditContext ssh_audit_init(SshAuditParams params)
{
  SshAuditContext context;
  int i;

  context = ssh_xmalloc(sizeof(struct SshAuditContextRec));
#ifdef WIN32
  context->win_syslog_source_name = params->win_syslog_source_name;
#endif /* WIN32 */
  context->log_filename = params->log_filename;
  context->facility = params->facility;
  context->severity = params->severity;
  if (context->log_filename)
    context->out_file = fopen((char *) context->log_filename, "a+wt");
  else
    context->out_file = NULL;

  /* Allow all events to be audited */
  for(i=0; i < SSH_AUDIT_MAX_VALUE; i++) 
    context->ssh_audit_event_allowed[i] = TRUE;
  return context;
}

/* 
 * Inserts specified event into log file specified in context.
 * event parameter specifies the audited event. Each element after event 
 * must start with a SshAuditformat type followed by arguments of the 
 * appropriate type, and the list must end with SSH_AUDIT_ARGUMENT_END.
 */
void ssh_audit_event(SshAuditContext context, SshAuditEvent event, ...)
{
  size_t bytes;
  va_list ap;
  SshBuffer *audit_info, *formated_str;
  char *audit_time;

  if (context == NULL) return;

  if ((event < 0) || (event > SSH_AUDIT_MAX_VALUE)) return;
  /* Check if given event is allowed */
  if (!context->ssh_audit_event_allowed[(int)event]) return;

  /* Initialize a buffer for output string */
  audit_info = ssh_buffer_allocate();

  /* Start constructing string which will be inserted into audit log.*/
  /* Start with inserting the name of the event.*/
  /* then date and time */
  audit_time = ssh_time_string(ssh_time());
  ssh_buffer_append_cstrs(audit_info, 
                          ssh_find_keyword_name(ssh_audit_event_title, 
                                                (int)event),
                          ": ", audit_time, ": ", 
                          NULL); 
  ssh_xfree(audit_time);

  /* Handle the variable list*/
  va_start(ap, event);
  formated_str = ssh_format_audit_string(ap);
  va_end(ap);

  /* Insert given parameters into string*/
  ssh_buffer_append(audit_info, 
                    ssh_buffer_ptr(formated_str),
                    ssh_buffer_len(formated_str));
  ssh_buffer_append(audit_info, (unsigned char *) "\0", 1);

  /* Output the log message*/
  ssh_send_log_message(context, ssh_buffer_ptr(audit_info));

  ssh_buffer_free(formated_str);
  ssh_buffer_free(audit_info);
}

/*
 * Disables or enables events listed from given context. State is either TRUE
 * or FALSE. After that is variable number argument list, which declares 
 * auditable events to be allowed or disallowed. Variable list MUST end with 
 * SSH_AUDIT_EVENT_END.
 */
void ssh_audit_change_event_state(SshAuditContext context, Boolean state, ...)
{
  va_list ap;
  int i = 0;

  if (context == NULL) return;
  va_start(ap, state);
  while (i != SSH_AUDIT_EVENT_END)
  {
    i = va_arg(ap, SshAuditEvent);
    context->ssh_audit_event_allowed[i] = state;
  }
  va_end(ap);
}
