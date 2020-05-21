/*

trkex.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Key exchange methods.

*/

/*
 * $Id: trkex.c,v 1.31 1999/05/04 19:21:01 kivinen Exp $
 * $Log: trkex.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbufaux.h"
#include "sshgetput.h"
#include "sshmsgs.h"
#include "trcommon.h"
#include "trkex.h"
#include "sshencode.h"
#include "ssh2pubkeyencode.h"
#include "sshcipherlist.h"
#include "sshdebug.h"

/* forward definitions */

Boolean ssh_kex_derive_keys(SshTransportCommon tr);
void ssh_kex_keycheck_callback(Boolean result, void *ctx);

/* Prepares the client side for key exchange. */

void ssh_tr_client_init_kex(SshTransportCommon tr,
                            const char *service_name,
                            const char *server_host_name,
                            SshKeyCheckCallback key_check,
                            void *key_check_context)
{
  tr->service_name = ssh_xstrdup(service_name);
  tr->server_host_name = ssh_xstrdup(server_host_name);
  tr->key_check = key_check;
  tr->key_check_context = key_check_context;
}

/* Prepares the server side for key exchange. */

void ssh_tr_server_init_kex(SshTransportCommon tr,
                            SshPrivateKey private_host_key,
                            SshPrivateKey private_server_key,
                            const unsigned char *public_host_key_blob,
                            size_t public_host_key_blob_len)
{
  SshPublicKey public_server_key;
  unsigned char *buf;
  size_t len;

  assert(tr->private_host_key == NULL);
  if (ssh_private_key_copy(private_host_key, &tr->private_host_key) !=
      SSH_CRYPTO_OK)
    ssh_fatal("ssh_tr_server_init_kex: private host key copy failed");

  if (private_server_key)
    {
      if (ssh_private_key_copy(private_server_key, &tr->private_server_key) !=
          SSH_CRYPTO_OK)
        ssh_fatal("ssh_tr_server_init_kex: private server key copy failed");
    }
  else
    tr->private_server_key = NULL;

  tr->public_host_key_blob = ssh_buffer_allocate();
  ssh_buffer_append(tr->public_host_key_blob, public_host_key_blob,
                public_host_key_blob_len);

  /* Derive the public server key and construct a blob from it. */
  if (private_server_key)
    {
      public_server_key =
        ssh_private_key_derive_public_key(private_server_key);
      if (public_server_key == NULL)
        ssh_fatal("Deriving public server key from private key failed.");
      len = ssh_encode_pubkeyblob(public_server_key, &buf);
      if (len == 0)
        ssh_fatal("ssh_tr_server_init_kex: public server key encoding failed");
      ssh_public_key_free(public_server_key);
      tr->public_server_key_blob = ssh_buffer_allocate();
      ssh_buffer_append(tr->public_server_key_blob, buf, len);
      ssh_xfree(buf);
    }
  else
    tr->public_server_key_blob = NULL;
}

/* Generate and set up a diffie-hellman-group, the secret and a exchange
   value.
   returns a SshCryptoStatus. */

SshCryptoStatus ssh_kexdh_make_group(SshTransportCommon tr, 
                                     const char *group_name)
{
  int i;

  /* group1's p, lifted from draft-ietf-ipsec-oakley-02.txt
     "E.2. Well-Known Group 2:  a 1024 bit prime" */

  const char group1_p[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";

  /* group1's generator */
  const char group1_g[] = "2";

  /* we currently accept only this one group */

  if (strcmp(group_name, "diffie-hellman-group1") != 0)
    {  
      ssh_debug("ssh_kexdh_make_group: unsupported type %s",
                group_name);
      return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
    }

  /* read the p and the g */
  
  ssh_mp_set_str(tr->dh_p, group1_p, 16);
  ssh_mp_set_str(tr->dh_g, group1_g, 16);

  /*
    Randomize our secret value (x or y) and public value (e or f).
    We'll use only 192 bits of entropy for faster exponentiation. 

    For discussion, see:
      P. C. van Oorschot and M. J. Wiener, "On Diffie-Hellman Key Agreement
      with Short Exponents", proc. Eurocrypt 96
  */

  ssh_mp_set_ui(tr->dh_secret, 1);  
  for (i = 0; i < 24; i++)
    {
      ssh_mp_mul_2exp(tr->dh_secret, tr->dh_secret, 8);
      ssh_mp_add_ui(tr->dh_secret, tr->dh_secret, 
                 ssh_random_get_byte(tr->random_state));
    }
  
  ssh_mp_powm(tr->server ? tr->dh_f : tr->dh_e, 
           tr->dh_g, tr->dh_secret, tr->dh_p);

  return SSH_CRYPTO_OK;
}

/* Compute the shared secret and the exchange hash. Return TRUE on failure */

Boolean ssh_kexdh_compute_h(SshTransportCommon tr)
{
  SshIntC t;
  SshBuffer *buf;
  
  /* check that the public value is within the range */

  if (ssh_mp_cmp_ui(tr->server ? tr->dh_e : tr->dh_f, 2) <= 0)
    return TRUE;

  ssh_mp_init(t);
  ssh_mp_sub_ui(t, tr->dh_p, 2);
  if (ssh_mp_cmp(tr->dh_e, t) >= 0)
    {
      ssh_mp_clear(t);
      return TRUE;
    }
  ssh_mp_clear(t);

  /* compute the shared secret */

  ssh_mp_powm(tr->dh_k, tr->server ? tr->dh_e : tr->dh_f, 
           tr->dh_secret, tr->dh_p);

  /* ok, compute the exchange hash */
  
  buf = ssh_buffer_allocate();

  if (tr->server)
    {
      ssh_encode_buffer(buf, 
                        SSH_FORMAT_UINT32_STR, 
                          tr->remote_version, strlen(tr->remote_version),
                        SSH_FORMAT_UINT32_STR, 
                          tr->own_version, strlen(tr->own_version),
                        SSH_FORMAT_END);
    }
  else
    {
      ssh_encode_buffer(buf, 
                        SSH_FORMAT_UINT32_STR, 
                          tr->own_version, strlen(tr->own_version),
                        SSH_FORMAT_UINT32_STR, 
                          tr->remote_version, strlen(tr->remote_version),
                        SSH_FORMAT_END);
    }

  ssh_encode_buffer(buf,
                    SSH_FORMAT_UINT32_STR, 
                      ssh_buffer_ptr(tr->client_kexinit_packet),
                      ssh_buffer_len(tr->client_kexinit_packet),
                    SSH_FORMAT_UINT32_STR,
                      ssh_buffer_ptr(tr->server_kexinit_packet),
                      ssh_buffer_len(tr->server_kexinit_packet),
                    SSH_FORMAT_UINT32_STR, 
                      ssh_buffer_ptr(tr->public_host_key_blob),
                      ssh_buffer_len(tr->public_host_key_blob),
                    SSH_FORMAT_END);
  buffer_put_mp_int_ssh2style(buf, tr->dh_e);
  buffer_put_mp_int_ssh2style(buf, tr->dh_f);
  buffer_put_mp_int_ssh2style(buf, tr->dh_k);

  ssh_hash_reset(tr->hash);
  ssh_hash_update(tr->hash, ssh_buffer_ptr(buf), ssh_buffer_len(buf));
  ssh_hash_final(tr->hash, tr->exchange_hash);
  tr->exchange_hash_len = ssh_hash_digest_length(tr->hash);

  /* our first key exchange ? */

  if (tr->doing_rekey == FALSE)
    {
      memcpy(tr->session_identifier, tr->exchange_hash, tr->exchange_hash_len);
      tr->session_identifier_len = tr->exchange_hash_len;
    }



#if 0
  ssh_debug("ssh_kexdh_compute_h (%s)", tr->server ? "server" : "client");
  printf(" e = ");
  ssh_mp_out_str(stdout, 16, tr->dh_e);
  printf("\n f = ");    
  ssh_mp_out_str(stdout, 16, tr->dh_f);
  printf("\n secret = ");    
  ssh_mp_out_str(stdout, 16, tr->dh_secret);
  printf("\n k = ");    
  ssh_mp_out_str(stdout, 16, tr->dh_k);
  printf("\n g = ");    
  ssh_mp_out_str(stdout, 16, tr->dh_g);
  printf("\n p = ");    
  ssh_mp_out_str(stdout, 16, tr->dh_p);

  printf("\n -- exchange hash computed over -- \n");
  buffer_dump(buf);
  printf("\n h = \n");
  ssh_debug_hexdump(0, tr->exchange_hash, tr->exchange_hash_len);
  printf(" session_id = \n");
  ssh_debug_hexdump(0, tr->session_identifier, tr->session_identifier_len);
  printf("\n");
#endif

  ssh_buffer_free(buf);

  return FALSE;
}


/* client makes the diffie-hellman kex1, which is a SSH_MSG_KEXDH_INIT */

SshBuffer *ssh_kexdh_client_make_kex1(SshTransportCommon tr)
{
  SshBuffer *packet;

  /* generate group1 & the exchange value for the client */
  if (ssh_kexdh_make_group(tr, "diffie-hellman-group1") != SSH_CRYPTO_OK)
    return NULL;  

  /* Allocate and construct a KEXDH_INIT packet. */

  packet = ssh_buffer_allocate();  
  buffer_put_char(packet, SSH_MSG_KEXDH_INIT);
  buffer_put_mp_int_ssh2style(packet, tr->dh_e);

  return packet;
}

/* server recieves client's kex1, which is a SSH_MSG_KEXDH_INIT */

Boolean ssh_kexdh_server_input_kex1(SshTransportCommon tr, SshBuffer *input)
{
  unsigned char code;

  /* decode the first byte to see that we got a SSH_MSG_KEXDH_INIT */

  code = buffer_get_char(input);

  if (code != SSH_MSG_KEXDH_INIT)
    {
      ssh_debug("ssh_kexdh_server_input_kex1: expected SSH_MSG_KEXDH_INIT"
                ", got %d", (int) code);
      ssh_buffer_free(input);
      return FALSE;
    }

  /* server generates the group, secret, and the exchange value */

  if (ssh_kexdh_make_group(tr, "diffie-hellman-group1") != SSH_CRYPTO_OK)
    return FALSE;  
  buffer_get_mp_int_ssh2style(input, tr->dh_e);

  return TRUE;
}

/* server creates a SSH_MSG_KEXDH_REPLY (kex2) */

SshBuffer *ssh_kexdh_server_make_kex2(SshTransportCommon tr)
{
  SshBuffer *packet;
  unsigned char *signature;
  size_t sig_len;

  /* compute the exchange hash H */

  if (ssh_kexdh_compute_h(tr))
    return NULL;

  sig_len = ssh_private_key_max_signature_output_len(tr->private_host_key);
  signature = ssh_xmalloc(sig_len);

  /* do the private key operation to sign H */

  if (ssh_private_key_sign(tr->private_host_key, 
                           tr->exchange_hash, tr->exchange_hash_len,
                           signature, sig_len, &sig_len,
                           tr->random_state) != SSH_CRYPTO_OK)
    return NULL;

  /* construct the packet */

  packet = ssh_buffer_allocate();
  ssh_encode_buffer(packet, 
                    SSH_FORMAT_CHAR, (unsigned int) SSH_MSG_KEXDH_REPLY,
                    SSH_FORMAT_UINT32_STR, 
                      ssh_buffer_ptr(tr->public_host_key_blob),
                      ssh_buffer_len(tr->public_host_key_blob),
                    SSH_FORMAT_END);
  buffer_put_mp_int_ssh2style(packet, tr->dh_f);
  buffer_put_uint32_string(packet, signature, sig_len);

  memset(signature, 0, sig_len);
  ssh_xfree(signature);

  /* we're ready to derive the keys */
  ssh_kex_derive_keys(tr);

  return packet;
}


/* A simple callback for the key check function */

/* Internal struct for the callback, and the calling function. */
typedef struct SshKex2KeyCheckCallbackContextRec
{
  SshBuffer *input;
  size_t pubkey_len;
  unsigned char *pubkey;
  size_t sig_len;
  unsigned char *signature;
  SshKex2CompletionProc completion;
  
} *SshKex2KeyCheckCallbackContext;

/* This function is called by the registered key check function. (in
   ssh2 it is ssh_client_key_check in sshclient.c) */
void ssh_kex_keycheck_callback(Boolean result, void *ctx)
{
  SshTransportCommon tr;
  SshKex2KeyCheckCallbackContext callback_context;
  
  tr = (SshTransportCommon) ctx;

  callback_context = tr->key_check_callback_context;
  
  tr->key_check_returned = TRUE;
  tr->key_check_result = result;

  if (tr->key_check_result == FALSE)
    {
      if (callback_context->pubkey != NULL)
        ssh_xfree(callback_context->pubkey);
    }
  else
    {
      tr->public_host_key_blob = ssh_buffer_allocate();
      ssh_buffer_append(tr->public_host_key_blob, callback_context->pubkey,
                        callback_context->pubkey_len);
      ssh_xfree(callback_context->pubkey);

      buffer_get_mp_int_ssh2style(callback_context->input, tr->dh_f);  
      callback_context->signature =
        buffer_get_uint32_string(callback_context->input,
                                 &(callback_context->sig_len));

      /* ok, verify the signature */

      if (ssh_kexdh_compute_h(tr))
        tr->key_check_result = FALSE;

      if (ssh_public_key_verify_signature(tr->public_host_key,
                                          callback_context->signature,
                                          callback_context->sig_len,
                                          tr->exchange_hash, 
                                          tr->exchange_hash_len) == FALSE)
        {
          ssh_xfree(callback_context->signature);
          tr->key_check_result = FALSE;
        }

      memset(callback_context->signature, 0, callback_context->sig_len);
      ssh_xfree(callback_context->signature);

      /* we're ready to derive the keys */
      ssh_kex_derive_keys(tr);
    }
  
  /* Call the supplied callback.*/
  (*callback_context->completion)(tr);

  ssh_xfree(callback_context);
}

/* client parses the server's SSH_MSG_KEXDH_REPLY (kex2) */

void ssh_kexdh_client_input_kex2(SshTransportCommon tr, SshBuffer *input,
                                 SshKex2CompletionProc finalize_callback)
{
  unsigned int code;
  unsigned char *pubkey;  
  size_t pubkey_len;
  char *pubkeytype;
  SshKex2KeyCheckCallbackContext callback_context;
  
  if ((code = buffer_get_char(input)) != SSH_MSG_KEXDH_REPLY)
    {
      ssh_debug("ssh_kexdh_client_input_kex2: received illegal packet %d",
                code);
      return;
    }

  /* get the public key */

  if (ssh_decode_buffer(input, SSH_FORMAT_UINT32_STR, &pubkey, &pubkey_len,
                        SSH_FORMAT_END) == 0)
    {
      ssh_debug("ssh_kexdh_client_input_kex2: failed to parse the pubkey "
                "and certificates.");
      return;
    }

  if (tr->public_host_key_blob != NULL)
    ssh_buffer_free(tr->public_host_key_blob);

  pubkeytype = ssh_pubkeyblob_type(pubkey, pubkey_len);
  if (ssh_cipher_list_contains(tr->host_key_names, pubkeytype))
    {
      tr->public_host_key = ssh_decode_pubkeyblob(pubkey, pubkey_len);
    }
  else
    {
      ssh_debug("received pubkey of type %s not in list %s\n",
                pubkeytype, tr->host_key_names);
    }
  ssh_xfree(pubkeytype);

  if (tr->public_host_key == NULL)
    {
      ssh_debug("ssh_kexdh_client_input_kex2: invalid host key.");
      return;
    }

  
  /* Check the host key */
  tr->key_check_returned = FALSE;
  if (tr->key_check)
    {
      callback_context =
        ssh_xcalloc(1, sizeof(struct SshKex2KeyCheckCallbackContextRec));

      tr->key_check_callback_context = callback_context;

      callback_context->pubkey = pubkey;
      callback_context->pubkey_len = pubkey_len;
      callback_context->signature = NULL;
      callback_context->sig_len = 0;
      callback_context->completion = finalize_callback;
      callback_context->input = input;

      (*tr->key_check)(tr->server_host_name, pubkey, pubkey_len,
                       ssh_kex_keycheck_callback, tr, tr->key_check_context);

    }
  /* Rest is done in ssh_kex_keycheck_callback(). */
}

/* derive one key */

void ssh_kex_derive_key(SshTransportCommon tr,
                        unsigned char id,
                        unsigned char *key_ptr, size_t key_len)
{
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t len, hash_len, i;
  SshBuffer buffer;

  hash_len = ssh_hash_digest_length(tr->hash);

  /* Compute the first part of the key. */

  ssh_hash_reset(tr->hash);
  if (! tr->ssh_old_keygen_bug_compat)
    {
      ssh_buffer_init(&buffer);
      buffer_put_mp_int_ssh2style(&buffer, tr->dh_k);
      ssh_hash_update(tr->hash, 
                      ssh_buffer_ptr(&buffer),
                      ssh_buffer_len(&buffer));
    }
  ssh_hash_update(tr->hash, tr->exchange_hash, tr->exchange_hash_len);
  ssh_hash_update(tr->hash, &id, 1);
  ssh_hash_update(tr->hash, 
                  tr->session_identifier, 
                  tr->session_identifier_len);
  ssh_hash_final(tr->hash, buf);

  /* Expand the key. Note that this will not increase entropy in 
     any real sense. */

  for (i = 0; i < key_len; /*NOTHING*/)
    {
      len = key_len - i;
      len = len > hash_len ? hash_len : len;
      memcpy(&key_ptr[i], buf, len);
      i += len;

      if (i < key_len)
        {
          ssh_hash_reset(tr->hash);
          if (! tr->ssh_old_keygen_bug_compat)
            {
              ssh_hash_update(tr->hash, 
                              ssh_buffer_ptr(&buffer),
                              ssh_buffer_len(&buffer));
            }
          ssh_hash_update(tr->hash, tr->exchange_hash, tr->exchange_hash_len);
          ssh_hash_update(tr->hash, key_ptr, i);
          ssh_hash_final(tr->hash, buf);
        }
    }

  if (! tr->ssh_old_keygen_bug_compat)
    {
      memset(ssh_buffer_ptr(&buffer), 0, ssh_buffer_len(&buffer));
      ssh_buffer_uninit(&buffer);
    }
  memset(buf, 0, sizeof(buf));
}

/* Derive all keys */

Boolean ssh_kex_derive_keys(SshTransportCommon tr)
{
  ssh_kex_derive_key(tr, 'A', tr->c_to_s.iv, sizeof(tr->c_to_s.iv));
  ssh_kex_derive_key(tr, 'B', tr->s_to_c.iv, sizeof(tr->s_to_c.iv));
  ssh_kex_derive_key(tr, 'C', tr->c_to_s.encryption_key, 
                     sizeof(tr->c_to_s.encryption_key));
  ssh_kex_derive_key(tr, 'D', tr->s_to_c.encryption_key, 
                     sizeof(tr->s_to_c.encryption_key));
  ssh_kex_derive_key(tr, 'E', tr->c_to_s.integrity_key, 
                     sizeof(tr->c_to_s.integrity_key));
  ssh_kex_derive_key(tr, 'F', tr->s_to_c.integrity_key, 
                     sizeof(tr->s_to_c.integrity_key));

  return TRUE;
}

/* Returns NULL.  This is used as a kex1/kex2 packet generator when no such
   packet is sent for the kex type. */

SshBuffer *ssh_kex_return_no_packet(SshTransportCommon tr)
{
  return NULL;
}

/* Definitions of supported key exchange algorithms. */

const struct SshKexTypeRec ssh_kex_algorithms[] =
{
  { "diffie-hellman-group1-sha1", "sha1",
    FALSE, TRUE,
    ssh_kexdh_client_make_kex1, ssh_kex_return_no_packet,
    ssh_kex_return_no_packet, ssh_kexdh_server_make_kex2,
    NULL, ssh_kexdh_server_input_kex1,
    ssh_kexdh_client_input_kex2, NULL },

#if 0  
  { "double-encrypting-sha1", "sha1",
    TRUE, FALSE,
    ssh_kex_return_no_packet, ssh_kexde_server_make_hostkey,
    ssh_kexde_client_make_sessionkey, ssh_kex_return_no_packet,
    ssh_kexde_client_input_kex1, NULL,
    NULL, ssh_kexde_server_input_kex2 },
#endif
  
  { NULL }
};

/* Returns a list of supported key exchange algorithms.  The caller is must
   free the list with ssh_xfree. */

char *ssh_kex_get_supported()
{
  SshBuffer buffer;
  int i;
  char *cp;

  ssh_buffer_init(&buffer);
  for (i = 0; ssh_kex_algorithms[i].name != NULL; i++)
    {
      if (ssh_buffer_len(&buffer) > 0)
        ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
      ssh_buffer_append(&buffer, (unsigned char *) ssh_kex_algorithms[i].name,
                    strlen(ssh_kex_algorithms[i].name));
    }
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  cp = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
  return cp;
}

/* Returns the SshKexType object for the kex method, or NULL if not found. */

SshKexType ssh_kex_lookup(const char *name)
{
  int i;
  for (i = 0; ssh_kex_algorithms[i].name != NULL; i++)
    if (strcmp(ssh_kex_algorithms[i].name, name) == 0)
      return &ssh_kex_algorithms[i];
  return NULL;
}

/* Return a SshHash object that matches the key exchange method, or
 * NULL on error. name is the name of the key exchange method. */

SshHash ssh_kex_allocate_hash(const char *name)
{
  int i;
  SshHash hash;
  
  for (i = 0; ssh_kex_algorithms[i].name != NULL; i++)
    {
      if (strcmp(ssh_kex_algorithms[i].name, name) == 0)
        {  
          if (ssh_hash_allocate(ssh_kex_algorithms[i].hash_name, &hash)
              != SSH_CRYPTO_OK)
            return NULL;
          return hash;
        }
    }  
  return NULL;  
}
