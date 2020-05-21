/*

sshtrans.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH transport layer protocol implementation.  This layer performs
encryption, integrity, server host authentication, and compression.

*/

/*
 * $Id: sshtrans.c,v 1.13 1999/04/16 14:41:23 sjl Exp $
 * $Log: sshtrans.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshtrans.h"
#include "sshcrypt.h"
#include "trcommon.h"
#include "namelist.h"
#include "sshcipherlist.h"

#define DEFAULT_CIPHERS         "3des-cbc,idea-cbc,blowfish-cbc,none"
#define DEFAULT_MACS            "hmac-sha,hmac-md5,sha-8,md5-8,sha,none"
#define DEFAULT_COMPRESSIONS    "none,zlib"
#define DEFAULT_KEXS            "diffie-hellman-group1-sha1,"\
                                "double-encrypting-sha1"

/* Creates default transport protocol parameter structure.  This structure
   can be modified to choose different parameters. */

SshTransportParams ssh_transport_create_params(void)
{
  SshTransportParams params;
  char *hlp;

  params = ssh_xmalloc(sizeof(*params));
  params->kex_algorithms = ssh_xstrdup(DEFAULT_KEXS);
  hlp = ssh_public_key_get_supported();
  params->host_key_algorithms = ssh_public_key_list_canonialize(hlp);
  ssh_xfree(hlp);
  params->hash_algorithms = ssh_hash_get_supported();
  params->compressions_c_to_s = ssh_xstrdup(DEFAULT_COMPRESSIONS);
  params->compressions_s_to_c = ssh_xstrdup(DEFAULT_COMPRESSIONS);
  params->ciphers_c_to_s = ssh_name_list_intersection_cipher(DEFAULT_CIPHERS);
  params->ciphers_s_to_c = ssh_name_list_intersection_cipher(DEFAULT_CIPHERS);
  params->macs_c_to_s = ssh_name_list_intersection_mac(DEFAULT_MACS);
  params->macs_s_to_c = ssh_name_list_intersection_mac(DEFAULT_MACS);
  return params;
}

/* Frees the protocol parameter structure.  This function should normally not
   be called by applications as the parameters are freed automatically.
   However, if the application gets the parameters just to know what the
   defaults are, it can use this to destroy the parameters. */

void ssh_transport_destroy_params(SshTransportParams params)
{
  ssh_xfree(params->kex_algorithms);
  ssh_xfree(params->host_key_algorithms);
  ssh_xfree(params->hash_algorithms);
  ssh_xfree(params->compressions_c_to_s);
  ssh_xfree(params->compressions_s_to_c);
  ssh_xfree(params->ciphers_c_to_s);
  ssh_xfree(params->ciphers_s_to_c);
  ssh_xfree(params->macs_c_to_s);
  ssh_xfree(params->macs_s_to_c);
  ssh_xfree(params);
}

/* Takes a stream which is supposed to be a connection to the server, and
 * performs client-side processing for the transport layer.  Returns
 * a SshStream object representing the transport layer. */

SshStream ssh_transport_client_wrap(SshStream stream,
                                    SshRandomState random_state,
                                    const char *application_version,
                                    const char *service,
                                    SshTransportParams params,
                                    const char *server_host_name,
                                    SshKeyCheckCallback key_check,
                                    void *context,
                                    SshVersionCallback version_callback,
                                    void *version_context)
{
  SshTransportCommon tr;

  if (params == NULL)
    params = ssh_transport_create_params();

  tr = ssh_tr_create(stream, FALSE, TRUE, version_callback != NULL,
                     application_version,
                     random_state, params);
  tr->version_callback = version_callback;
  tr->version_context = version_context;

  ssh_tr_client_init_kex(tr, service, server_host_name, key_check, context);
  
  return ssh_tr_create_final(tr);
}

/* Takes a stream which is supposed to be a connection to the client,
   and performs server-side processing for the transport layer.  Returns
   a SshStream object representing the transport layer. */

SshStream ssh_transport_server_wrap(SshStream stream,
                                    SshRandomState random_state,
                                    const char *application_version,
                                    SshTransportParams params,
                                    SshPrivateKey private_host_key,
                                    SshPrivateKey private_server_key,
                                    const unsigned char *public_host_key_blob,
                                    unsigned int public_host_key_blob_len,
                                    SshVersionCallback version_callback,
                                    void *version_context)
{
  SshTransportCommon tr;

  if (params == NULL)
    params = ssh_transport_create_params();

  tr = ssh_tr_create(stream, TRUE, TRUE, version_callback != NULL,
                     application_version,
                     random_state, params);
  tr->version_callback = version_callback;
  tr->version_context = version_context;

  ssh_tr_server_init_kex(tr, private_host_key, private_server_key,
                         public_host_key_blob, public_host_key_blob_len);
  
  return ssh_tr_create_final(tr);
}

/* Returns statistics information about the transport layer object. */

void ssh_transport_get_statistics(SshStream stream,
                                  SshTransportStatistics *stats)
{
  SshTransportCommon tr;

  /* Verify that this is a transport stream. */
  if (ssh_stream_get_methods(stream) != &ssh_tr_methods)
    {
      memset(stats, 0, sizeof(*stats));
      return;
    }

  /* Get the real object. */
  tr = (SshTransportCommon)ssh_stream_get_context(stream);
  
  /* Return statistics data. */
  stats->compressed_incoming_bytes = tr->compressed_incoming_bytes;
  stats->uncompressed_incoming_bytes = tr->uncompressed_incoming_bytes;
  stats->compressed_outgoing_bytes = tr->compressed_outgoing_bytes;
  stats->uncompressed_outgoing_bytes = tr->uncompressed_outgoing_bytes;
  stats->incoming_packets = tr->incoming_sequence_number;
  stats->outgoing_packets = tr->outgoing_sequence_number;
}

/* Return application level compatibility flags. Note that this must
   not be called if tr has become invalid for some reason. The return
   struct should be freed by the caller, when it is no longer
   needed. */
void ssh_transport_get_compatibility_flags(SshStream stream,
                                           SshTransportCompat *compat_flags)
{
  SshTransportCommon tr;
  SshTransportCompat rec;
  
  /* Verify that this is a transport stream. */
  if (ssh_stream_get_methods(stream) != &ssh_tr_methods)
    {
      memset(compat_flags, 0, sizeof(*compat_flags));
      return;
    }

  /* Get the real object. */
  tr = (SshTransportCommon)ssh_stream_get_context(stream);

  rec = ssh_xcalloc(1, sizeof(*rec));
  rec->publickey_draft_incompatility =
    &(tr->ssh_old_publickey_bug_compat);

  *compat_flags = rec;
}
