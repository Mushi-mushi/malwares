/*

pgp_key.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1999 SSH Communications Security, Finland
                   All rights reserved

Parse pgp keyblobs.

*/
/*
 * $Id: pgp_key.c,v 1.8 1999/05/04 08:54:03 tri Exp $
 * $Log: pgp_key.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef WITH_PGP
#include "sshmatch.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshpgp.h"

#define SSH_DEBUG_MODULE "SshPgpKey"

/* Functions to build private keys compatible with SSH Crypto Library.
   Keys are derived from public keys and components of the secret key. */   
SshPrivateKey ssh_pgp_define_secret_rsa_key(SshPublicKey public_key,
                                            SshInt *d,
                                            SshInt *p,
                                            SshInt *q,
                                            SshInt *u);
SshPrivateKey ssh_pgp_define_secret_elgamal_key(SshPublicKey public_key,
                                            SshInt *x);
SshPrivateKey ssh_pgp_define_secret_dsa_key(SshPublicKey public_key,
                                            SshInt *x);

/* Decode pgp encoded integer. */
size_t ssh_pgp_mpz_decode(const unsigned char *data, int len, SshInt *z);

static size_t bitbytes(size_t bits);

static size_t bitbytes(size_t bits)
{
  return (bits / 8) + ((bits % 8 != 0) ? 1 : 0);
}

size_t ssh_pgp_public_key_decode(const unsigned char *data, 
                                 size_t len, 
                                 SshPgpPublicKey *key)
{
  int version, key_type, pk_algorithm_byte;
  SshUInt32 generation_time, validity_time;
  int i;
  SshInt z[4];
  size_t skiptot;
  int skip;
  SshPgpPublicKey r = NULL;
  SshCryptoStatus cr;
  SshHash hash;
  SshUInt32 key_id_high, key_id_low;
  char *key_fingerprint;
  const unsigned char *pubkey_data;
  size_t pubkey_start_offset, pubkey_data_len;

  SSH_ASSERT(key != NULL);

  skiptot = 0;

  if (len < 12)
    return 0; /* Too short to be a valid key packet */

  version = (int)data[0];
  generation_time = ((((SshUInt32)data[1]) << 24) |
                     (((SshUInt32)data[2]) << 16) |
                     (((SshUInt32)data[3]) << 8) |
                     ((SshUInt32)data[4]));
  len -= 5;
  data += 5;
  skiptot += 5;

  for (i = 0; i < 4; i++)
    ssh_mp_init(&(z[i]));

  if ((version == 2) || (version == 3)) 
    {
      validity_time = ((((SshUInt32)data[0]) << 8) |
                       ((SshUInt32)data[1]));
      pk_algorithm_byte = data[2];
      len -= 3;
      data += 3;
      skiptot += 3;
      pubkey_data = data;
      pubkey_start_offset = skiptot;
      switch (pk_algorithm_byte) 
        {
        case SSH_PGP_PK_ALGORITHM_RSA:
        case SSH_PGP_PK_ALGORITHM_RSA_ENCRYPT_ONLY:
        case SSH_PGP_PK_ALGORITHM_RSA_SIGN_ONLY:
          key_type = SSH_PGP_KEY_TYPE_RSA_PUBLIC;
          for (i = 0; i < 2; i++)
            {
              skip = ssh_pgp_mpz_decode(data, len, &z[i]);
              if (skip < 1) 
                {
                  /* Unexpected end of data */
                  goto packet_parsing_failed;
                }
              len -= skip;
              data += skip;
              skiptot += skip;
            }
#if 0
          for (i = 0; i < 2; i++)
            {
              char *hlp;
              hlp = ssh_mp_get_str(NULL, 16, &z[i]);
              printf("z[%d] = %s\n", i, hlp);
              ssh_xfree(hlp);
            }
#endif
          break;

        default:
          /* Unexpected algorithm type for version 2 or 3 */
          SSH_DEBUG(3, ("wrong pk algorithm %d for old packet version %d\n",
                        pk_algorithm_byte, version));
          goto packet_parsing_failed;
        }
      pubkey_data_len = skiptot - pubkey_start_offset;
      cr = ssh_hash_allocate("md5", &hash);
      if (cr == SSH_CRYPTO_OK) 
        {
          unsigned char digest[16];
          char print[64];
          int l1, l2;
          SshInt x1;

          /* Hash the payload of the public key material */
          l1 = bitbytes(((((int)(pubkey_data[0])) << 8) |
                         ((int)(pubkey_data[1]))));
          ssh_hash_update(hash, &(pubkey_data[2]), l1);
          l2 = bitbytes(((((int)(pubkey_data[l1 + 2])) << 8) | 
                         ((int)(pubkey_data[l1 + 3]))));
          ssh_hash_update(hash, &(pubkey_data[l1 + 4]), l2);
          ssh_hash_final(hash, digest);
          for (i = 0; i < 8; i++)
            {
              snprintf(&(print[i * 3]), 
                       sizeof (print) - (i * 3), 
                       "%02X     ",
                       (((unsigned int)digest[i])));
            }
          for (i = 0; i < 8; i++)
            {
              snprintf(&(print[((i + 8) * 3) + 1]), 
                       sizeof (print) - (((i + 8) * 3) + 1), 
                       "%02X     ",
                       (((unsigned int)digest[i + 8])));
            }
          key_fingerprint = ssh_xstrdup(print); 
          ssh_hash_free(hash);
          /* Calculate id from lower bits of public exponent. */
          ssh_mp_init_set(&x1, &(z[0]));
          key_id_low = ssh_mp_get_ui(&x1) & 0xffffffff;
          ssh_mp_div_2exp(&x1, &x1, 32);
          key_id_high = ssh_mp_get_ui(&x1) & 0xffffffff;
          ssh_mp_clear(&x1);
        }
      else
        {
          /* Make dummy fingerprint and id. */
          key_fingerprint = 
            ssh_xstrdup("?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??");
          key_id_low = 0x00000000;
          key_id_high = 0x00000000;
        }
    } 
  else if (version == 4) 
    {
      validity_time = 0;
      pk_algorithm_byte = data[0];
      len--;
      data++;
      skiptot++;
      pubkey_data = data;
      pubkey_start_offset = skiptot; /* Save the current offset */
      switch (pk_algorithm_byte) 
        {
        case SSH_PGP_PK_ALGORITHM_RSA:
        case SSH_PGP_PK_ALGORITHM_RSA_ENCRYPT_ONLY:
        case SSH_PGP_PK_ALGORITHM_RSA_SIGN_ONLY:
          key_type = SSH_PGP_KEY_TYPE_RSA_PUBLIC;
          for (i = 0; i < 2; i++)
            {
              skip = ssh_pgp_mpz_decode(data, len, &z[i]);
              if (skip < 1) 
                {
                  /* Unexpected end of data */
                  goto packet_parsing_failed;
                }
              len -= skip;
              data += skip;
              skiptot += skip;
            }
#if 0
          for (i = 0; i < 2; i++)
            {
              char *hlp;
              hlp = ssh_mp_get_str(NULL, 16, &z[i]);
              printf("z[%d] = %s\n", i, hlp);
              ssh_xfree(hlp);
            }
#endif
          break;

        case SSH_PGP_PK_ALGORITHM_ELGAMAL_ENCRYPT_ONLY:
        case SSH_PGP_PK_ALGORITHM_ELGAMAL:
          key_type = SSH_PGP_KEY_TYPE_ELGAMAL_PUBLIC;
          for (i = 0; i < 3; i++)
            {
              skip = ssh_pgp_mpz_decode(data, len, &z[i]);
              if (skip < 1) 
                {
                  /* Unexpected end of data */
                  goto packet_parsing_failed;
                }
              len -= skip;
              data += skip;
              skiptot += skip;
            }
#if 0
          for (i = 0; i < 3; i++)
            {
              char *hlp;
              hlp = ssh_mp_get_str(NULL, 16, &z[i]);
              printf("z[%d] = %s\n", i, hlp);
              ssh_xfree(hlp);
            }
#endif
          break;

        case SSH_PGP_PK_ALGORITHM_DSA:
          key_type = SSH_PGP_KEY_TYPE_DSA_PUBLIC;
          for (i = 0; i < 4; i++)
            {
              skip = ssh_pgp_mpz_decode(data, len, &z[i]);
              if (skip < 1) 
                {
                  /* Unexpected end of data */
                  goto packet_parsing_failed;
                }
              len -= skip;
              data += skip;
              skiptot += skip;
            }
#if 0
          for (i = 0; i < 4; i++)
            {
              char *hlp;
              hlp = ssh_mp_get_str(NULL, 16, &z[i]);
              printf("z[%d] = %s\n", i, hlp);
              ssh_xfree(hlp);
            }
#endif
          break;

        default:
          SSH_DEBUG(3, ("unsupported pk algorithm %d\n", pk_algorithm_byte));
          goto packet_parsing_failed;
        }
      pubkey_data_len = skiptot - pubkey_start_offset;
      cr = ssh_hash_allocate("sha1", &hash);
      if (cr == SSH_CRYPTO_OK) 
        {
          char buf[9];
          unsigned char digest[20];
          char print[64];

          buf[0] = 0x99;
          buf[1] = skiptot >> 8;
          buf[2] = skiptot & 0xff;
          buf[3] = 4;
          buf[4] = (generation_time >> 24) & 0xff;
          buf[5] = (generation_time >> 16) & 0xff;
          buf[6] = (generation_time >> 8) & 0xff;
          buf[7] = generation_time & 0xff;
          buf[8] = pk_algorithm_byte;
          ssh_hash_update(hash, buf, 9);
          ssh_hash_update(hash, pubkey_data, pubkey_data_len);
          ssh_hash_final(hash, digest);
          for (i = 0; i < 5; i++) {
            snprintf(&(print[i * 5]), 
                     sizeof (print) - (i * 5), 
                     "%04X     ",
                     ((((unsigned int)digest[i * 2]) << 8) |
                      ((unsigned int)digest[(i * 2) + 1])));
          }
          for (i = 0; i < 5; i++) {
            snprintf(&(print[((i + 5) * 5) + 1]), 
                     sizeof (print) - (((i + 5) * 5) + 1), 
                     "%04X     ",
                     ((((unsigned int)digest[(i + 5) * 2]) << 8) |
                      ((unsigned int)digest[((i + 5) * 2) + 1])));
          }
          key_fingerprint = ssh_xstrdup(print); 
          key_id_high = ((((SshUInt32)digest[12]) << 24) |
                         (((SshUInt32)digest[13]) << 16) |
                         (((SshUInt32)digest[14]) << 8) |
                         ((SshUInt32)digest[15]));
          key_id_low = ((((SshUInt32)digest[16]) << 24) |
                        (((SshUInt32)digest[17]) << 16) |
                        (((SshUInt32)digest[18]) << 8) |
                        ((SshUInt32)digest[19]));
          ssh_hash_free(hash);
        }
      else
        {
          /* Make dummy fingerprint and id. */
          key_fingerprint = 
            ssh_xstrdup("???? ???? ???? ???? ????  ???? ???? ???? ???? ????");
          key_id_low = 0x00000000;
          key_id_high = 0x00000000;
        }
    } else {
      /* Unsupported key packet version */
      SSH_DEBUG(3, ("unsupported key packet version %d\n", version));
      return 0;
    }

  r = ssh_xcalloc(1, sizeof (*r));
  r->type = key_type;
  r->version = version;
  r->generation_time = generation_time;
  r->validity_time = validity_time;
  r->id_low = key_id_low;
  r->id_high = key_id_high;
  r->fingerprint = key_fingerprint;

  switch (key_type) 
    {
    case SSH_PGP_KEY_TYPE_RSA_PUBLIC:
      if (r != NULL) {
        cr = ssh_public_key_define(&(r->key), SSH_PGP_CANONICAL_RSA_NAME,
                                   SSH_PKF_MODULO_N, &(z[0]),
                                   SSH_PKF_PUBLIC_E, &(z[1]),
                                   SSH_PKF_END);
        if (cr != SSH_CRYPTO_OK)
          {
            r->key = NULL;
            SSH_DEBUG(3, ("ssh_public_key_define returns %d\n", cr));
          }
      }
      break;

    case SSH_PGP_KEY_TYPE_DSA_PUBLIC:
      if (r != NULL) 
        {
          cr = ssh_public_key_define(&(r->key), SSH_PGP_CANONICAL_DSA_NAME,
                                     SSH_PKF_PRIME_P, &(z[0]),
                                     SSH_PKF_PRIME_Q, &(z[1]),
                                     SSH_PKF_GENERATOR_G, &(z[2]),
                                     SSH_PKF_PUBLIC_Y, &(z[3]),
                                     SSH_PKF_END);
          if (cr != SSH_CRYPTO_OK)
            {
              r->key = NULL;      
              SSH_DEBUG(3, ("ssh_public_key_define returns %d\n", cr));
            }
        }
      break;

    case SSH_PGP_KEY_TYPE_ELGAMAL_PUBLIC:
      if (r != NULL) 
        {
          cr = ssh_public_key_define(&(r->key), SSH_PGP_CANONICAL_ELGAMAL_NAME,
                                     SSH_PKF_PRIME_P, &(z[0]),
                                     SSH_PKF_GENERATOR_G, &(z[1]),
                                     SSH_PKF_PUBLIC_Y, &(z[2]),
                                     SSH_PKF_END);
          if (cr != SSH_CRYPTO_OK)
            {
              r->key = NULL;      
              SSH_DEBUG(3, ("ssh_public_key_define returns %d\n", cr));
            }
        }
      break;

    default:
      /* Internal error.  Garbage left. */
      return 0;
    }

  if (key)
    *key = r;
  for (i = 0; i < 4; i++)
    ssh_mp_clear(&(z[i]));
  return skiptot;

 packet_parsing_failed:
  SSH_DEBUG(0, ("public key packet parsing failed."));
  for (i = 0; i < 4; i++)
    ssh_mp_clear(&(z[i]));
  if (r)
    {
      ssh_xfree(r->fingerprint);
      ssh_xfree(r);
    }
  return 0;
}

void ssh_pgp_public_key_free(SshPgpPublicKey key)
{
  SSH_ASSERT(key != NULL);

  if (key->key != NULL)
    ssh_public_key_free(key->key);
  ssh_xfree(key->fingerprint);
  memset(key, 'F', sizeof (*key));
  ssh_xfree(key);
}

size_t ssh_pgp_secret_key_decode(const unsigned char *data, 
                                 size_t len, 
                                 SshPgpSecretKey *key)
{
  return ssh_pgp_secret_key_decode_with_passphrase(data, 
                                                   len, 
                                                   "",
                                                   key);
}

size_t ssh_pgp_secret_key_decode_with_passphrase(const unsigned char *data, 
                                                 size_t len, 
                                                 const char *passphrase,
                                                 SshPgpSecretKey *key)
{
  SshPgpPublicKey public_key = NULL;
  SshPgpSecretKey r = NULL;
  SshPgpCipher cipher = NULL;
  SshCryptoStatus cs;
  SshInt y[4];
  size_t skiptot = 0, bits, bytes, mp_buf_origlen;
  int skip;
  int s2k_conv;
  int s2k_type;
  int s2k_hash;
  int s2k_count;
  unsigned char s2k_salt[8];
  int key_enc_method;
  unsigned char iv[8];
  unsigned char *mp_buf, *mp_buf_orig;
  int i, j;
  unsigned int checksum, pktchecksum;

  SSH_ASSERT(key != NULL);

  skip = ssh_pgp_public_key_decode(data, len, &public_key);
  if (skip == 0)
    return 0;
  len -= skip;
  data += skip;
  skiptot += skip;

  if (len < 24)
    {
      ssh_pgp_public_key_free(public_key);
      return 0; /* Too short to be a valid key packet */
    }

  for (i = 0; i < 4; i++)
    ssh_mp_init(&(y[i]));

  s2k_conv = data[0];
  len--;
  data++;
  skiptot++;
  if (s2k_conv == 0)
    {
      /* Key is in cleartext. */
      key_enc_method = 0;
      /* Initialize these only for sanity. */
      s2k_hash = 1;
      s2k_count = 1;
      s2k_type = SSH_PGP_S2K_TYPE_SIMPLE;
      memset(s2k_salt, 0, 8);
    }
  else if (s2k_conv == 255) 
    {
      key_enc_method = data[0];
      len--;
      data++;
      skiptot++;

      if (data[0] == 0)
        {
          s2k_hash = data[1];
          s2k_count = 1;
          s2k_type = SSH_PGP_S2K_TYPE_SIMPLE;
          memset(s2k_salt, 0, 8);
          len -= 2;
          data += 2;
          skiptot += 2;
        }
      else if (data[0] == 1)
        {
          s2k_hash = data[1];
          s2k_count = 1;
          s2k_type = SSH_PGP_S2K_TYPE_SALTED;
          memcpy(s2k_salt, &(data[2]), 8);
          len -= 10;
          data += 10;
          skiptot += 10;
        }
      else if (data[0] == 3)
        {
          s2k_hash = data[1];
          s2k_type = SSH_PGP_S2K_TYPE_SALTED_ITERATED;
          memcpy(s2k_salt, &(data[2]), 8);
          s2k_count = data[10];
          len -= 11;
          data += 11;
          skiptot += 11;
        }
    } 
  else 
    {
      key_enc_method = s2k_conv;
      s2k_hash = 1;
      s2k_count = 1;
      s2k_type = SSH_PGP_S2K_TYPE_SIMPLE;
      memset(s2k_salt, 0, 8);
    }
  if (key_enc_method != 0) 
    {
      memcpy(iv, data, 8);
      len -= 8;
      data += 8;
      skiptot += 8;
    }
  else
    {
      memset(iv, 0, 8);
    }

  r = ssh_xcalloc(1, sizeof (*r));
  r->public_key = public_key;
  r->key = NULL;
  r->decryption_failed = TRUE;

  if (key_enc_method != 0)
    {
      cs = ssh_pgp_cipher_allocate(key_enc_method,
                                   passphrase,
                                   s2k_type,
                                   s2k_hash,
                                   s2k_count,
                                   s2k_salt,
                                   FALSE,
                                   &cipher);
      if (cs != SSH_CRYPTO_OK)
        {
          cipher = NULL;
          goto key_decryption_failed;
        }
      else
        {
          ssh_pgp_cipher_transform(cipher, iv, iv, 8);
          memset(iv, 0, 8);
        }
    }
  else
    {
      cipher = NULL;
    }

  if ((key_enc_method == 0) || (cipher != NULL))
    {
      if ((public_key->version == 2) || (public_key->version == 3))
        {
          checksum = 0;
          if (key_enc_method == 0)
            {
              for (i = 0; i < 4; i++)
                {
                  skip = ssh_pgp_mpz_decode(data, len, &y[i]);
                  if (skip < 1) 
                    {
                      /* Unexpected end of data */
                      goto packet_parsing_failed;
                    }
                  for (j = 0; j < skip; j++)
                    checksum = (checksum + data[j]) % 0x10000;
                  len -= skip;
                  data += skip;
                  skiptot += skip;
                }
              if (len < 2)
                {
                  goto packet_parsing_failed;
                }
              else
                {
                  pktchecksum = ((((unsigned int)data[0]) << 8) |
                                 (((unsigned int)data[1])));
                  len -= 2;
                  data += 2;
                  skiptot += 2;
                }
#if 0
              for (i = 0; i < 4; i++)
                {
                  char *hlp;
                  hlp = ssh_mp_get_str(NULL, 16, &y[i]);
                  printf("y[%d] = %s\n", i, hlp);
                  ssh_xfree(hlp);
                }
              printf("checksum = 0x%04x   pkt = 0x%04x\n",
                     checksum, pktchecksum);
#endif
              if (checksum != pktchecksum)
                {
                  goto key_decryption_failed;
                }
              else
                {
                  r->decryption_failed = FALSE;
                }
            }
          else
            {
              for (i = 0; i < 4; i++)
                {
                  bits = (((int)data[0]) << 8) | ((int)data[1]);
                  bytes = bitbytes(bits);
                  len -= 2;
                  data += 2;
                  skiptot += 2;
                  if (bytes <= len)
                    {
                      mp_buf = ssh_xmalloc(bytes + 2);
                      mp_buf[0] = *(data - 2);
                      mp_buf[1] = *(data - 1);
                      ssh_pgp_cipher_resync(cipher);
                      ssh_pgp_cipher_transform(cipher, 
                                               &(mp_buf[2]), 
                                               data, 
                                               bytes);
                      for (j = 0; j < bytes + 2; j++)
                        checksum = (checksum + mp_buf[j]) % 0x10000;
                    }
                  else
                    {
                      goto packet_parsing_failed;
                    }
                  skip = ssh_pgp_mpz_decode(mp_buf, bytes + 2, &(y[i]));
                  if (skip < 1)
                    {
                      ssh_xfree(mp_buf);
                      goto packet_parsing_failed;
                    }
                  len -= (skip - 2);
                  data += (skip - 2);
                  skiptot += (skip - 2);
                  memset(mp_buf, 'F', bytes + 2);
                  ssh_xfree(mp_buf);
                }
              if (len < 2)
                {
                  goto packet_parsing_failed;
                }
              else
                {
                  pktchecksum = ((((unsigned int)data[0]) << 8) |
                                 (((unsigned int)data[1])));
                  len -= 2;
                  data += 2;
                  skiptot += 2;
                }
#if 0
              for (i = 0; i < 4; i++)
                {
                  char *hlp;
                  hlp = ssh_mp_get_str(NULL, 16, &y[i]);
                  printf("y[%d] = %s\n", i, hlp);
                  ssh_xfree(hlp);
                }
              printf("checksum = 0x%04x   pkt = 0x%04x\n",
                     checksum, pktchecksum);
#endif
              if (checksum != pktchecksum)
                {
                  goto key_decryption_failed;
                }
              else
                {
                  r->decryption_failed = FALSE;
                }
            }
          checksum = 0;
          pktchecksum = 0;
        }
      else if (public_key->version == 4)
        {
          checksum = 0;
          mp_buf = ssh_xmalloc(len);
          mp_buf_orig = mp_buf;
          mp_buf_origlen = len;
          if (key_enc_method == 0)
            {
              memcpy(mp_buf, data, len);
            }
          else
            {
              ssh_pgp_cipher_resync(cipher);
              ssh_pgp_cipher_transform(cipher, mp_buf, data, len);
            }
          switch (public_key->type)
            {
            case SSH_PGP_KEY_TYPE_RSA_PUBLIC:
              for (i = 0; i < 4; i++)
                {
                  skip = ssh_pgp_mpz_decode(mp_buf, len, &(y[i]));
                  if (skip < 1) 
                    {
                      /* Unexpected end of data */
                      ssh_xfree(mp_buf);
                      if (key_enc_method == 0)
                        goto packet_parsing_failed;
                      else
                        goto key_decryption_failed;
                    }
                  for (j = 0; j < skip; j++)
                    checksum = (checksum + mp_buf[j]) % 0x10000;
                  len -= skip;
                  data += skip;
                  mp_buf += skip;
                  skiptot += skip;
                }
              break;

            case SSH_PGP_KEY_TYPE_ELGAMAL_PUBLIC:
            case SSH_PGP_KEY_TYPE_DSA_PUBLIC:
              skip = ssh_pgp_mpz_decode(mp_buf, len, &y[0]);
              if (skip < 1) 
                {
                  /* Unexpected end of data */
                  ssh_xfree(mp_buf);
                  if (key_enc_method == 0)
                    goto packet_parsing_failed;
                  else
                    goto key_decryption_failed;
                }
              for (j = 0; j < skip; j++)
                checksum = (checksum + mp_buf[j]) % 0x10000;
              len -= skip;
              data += skip;
              mp_buf += skip;
              skiptot += skip;
              break;

            default:
              /* If this occures, someone has implemented new public key
                 types but didn't implement secret key parsing. */
              memset(mp_buf, 'F', len);
              ssh_xfree(mp_buf);
              goto key_decryption_failed;
            }
          if (len < 2)
            {
              ssh_xfree(mp_buf_orig);
              goto packet_parsing_failed;
            }
          else
            {
              pktchecksum = ((((unsigned int)mp_buf[0]) << 8) |
                             (((unsigned int)mp_buf[1])));
              len -= 2;
              data += 2;
              skiptot += 2;
            }
          memset(mp_buf_orig, 'F', mp_buf_origlen);
          ssh_xfree(mp_buf_orig);
#if 0
              for (i = 0; i < 4; i++)
                {
                  char *hlp;
                  if ((i == 0) || 
                      (public_key->type == SSH_PGP_KEY_TYPE_RSA_PUBLIC))
                    {
                      hlp = ssh_mp_get_str(NULL, 16, &y[i]);
                      printf("y[%d] = %s\n", i, hlp);
                      ssh_xfree(hlp);
                    }
                }
              printf("checksum = 0x%04x   pkt = 0x%04x\n",
                     checksum, pktchecksum);
#endif
          if (checksum != pktchecksum)
            {
              goto key_decryption_failed;
            }
          else
            {
              r->decryption_failed = FALSE;
            }
        }
      else
        {
          SSH_DEBUG(3, ("unknown key packet version %d", public_key->version));
        }
    }
  if (r->decryption_failed == FALSE)
    {
      /* If we are here and we have RSA key we have secret values
         d, p, q and u in y[0], y[1], y[2] and y[3] accordingly.  
         If we have DSA or El Gamal key, we have the secret exponent 
         x in y[0]. */
      /* Make ssh cryptolib secret key here XXX */
          switch (public_key->type)
            {
            case SSH_PGP_KEY_TYPE_RSA_PUBLIC:
              if (public_key->key)
                r->key = ssh_pgp_define_secret_rsa_key(public_key->key,
                                                       &(y[0]),
                                                       &(y[1]),
                                                       &(y[2]),
                                                       &(y[3]));
              break;

            case SSH_PGP_KEY_TYPE_ELGAMAL_PUBLIC:
              if (public_key->key)
                r->key = ssh_pgp_define_secret_elgamal_key(public_key->key,
                                                           &(y[0]));
              break;

            case SSH_PGP_KEY_TYPE_DSA_PUBLIC:
              if (public_key->key)
                r->key = ssh_pgp_define_secret_dsa_key(public_key->key,
                                                       &(y[0]));
              break;

            default:
              break;
            }
    }

 key_decryption_failed:
  if (cipher)
    ssh_pgp_cipher_free(cipher);
  for (i = 0; i < 4; i++)
    ssh_mp_clear(&(y[i]));
  *key = r;
  return skiptot;

 packet_parsing_failed:
  SSH_DEBUG(0, ("secret key packet parsing failed."));
  if (public_key)
    ssh_pgp_public_key_free(public_key);
  if (cipher)
    ssh_pgp_cipher_free(cipher);
  for (i = 0; i < 4; i++)
    ssh_mp_clear(&(y[i]));
  if (r)
    ssh_xfree(r);
  return 0;
}

void ssh_pgp_secret_key_free(SshPgpSecretKey key)
{
  SSH_ASSERT(key != NULL);

  if (key->public_key != NULL)
    ssh_pgp_public_key_free(key->public_key);
  if (key->key != NULL)
    ssh_private_key_free(key->key);
  memset(key, 'F', sizeof (*key));
  ssh_xfree(key);
}

/* Decode pgp encoded integer. */
size_t ssh_pgp_mpz_decode(const unsigned char *data, int len, SshInt *z)
{
  int bits, bytes;
  int i;

  if (len < 2)
    return 0;
  bits = (((int)data[0]) << 8) | ((int)data[1]);
  if (bits == 0) 
    {
      ssh_mp_set_ui(z, 0);
      return 2;
    }
  bytes = bitbytes(bits);
  if (len < (2 + bytes))
    return 0;
  ssh_mp_set_ui(z, 0);
  for (i = 0; i < bytes; i++) 
    {
      ssh_mp_mul_2exp(z, z, 8);
      ssh_mp_add_ui(z, z, data[2 + i]);
    }
  return 2 + bytes;
}

SshPrivateKey ssh_pgp_define_secret_rsa_key(SshPublicKey public_key,
                                            SshInt *d,
                                            SshInt *p,
                                            SshInt *q,
                                            SshInt *u)
{
  SshInt e, n;
  SshPrivateKey key = NULL;
  SshCryptoStatus cs;
  SshRandomState dummy_rnd_state;
  
  if (public_key == NULL)
    return NULL;
  SSH_ASSERT(d != NULL);
  SSH_ASSERT(p != NULL);
  SSH_ASSERT(q != NULL);
  SSH_ASSERT(u != NULL);
  ssh_mp_init(&e);
  ssh_mp_init(&n);
  dummy_rnd_state = ssh_random_allocate();

  cs = ssh_public_key_get_info(public_key,
                               SSH_PKF_MODULO_N, &n,
                               SSH_PKF_PUBLIC_E, &e,
                               SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    goto failed;
  cs = ssh_private_key_generate(dummy_rnd_state,
                                &key,
                                SSH_PGP_CANONICAL_RSA_NAME,
                                SSH_PKF_MODULO_N, &n,
                                SSH_PKF_PUBLIC_E, &e,
                                SSH_PKF_PRIME_P, p,
                                SSH_PKF_PRIME_Q, q,
                                SSH_PKF_SECRET_D, d,
                                SSH_PKF_INVERSE_U, u,
                                SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    {
      key = NULL;
      goto failed;
    }

 failed:
  ssh_mp_clear(&e);
  ssh_mp_clear(&n);
  ssh_random_free(dummy_rnd_state);
  return key;
}

SshPrivateKey ssh_pgp_define_secret_elgamal_key(SshPublicKey public_key,
                                                SshInt *x)
{
  SshInt p, g, y;
  SshPrivateKey key = NULL;
  SshCryptoStatus cs;
  SshRandomState dummy_rnd_state;

  if (public_key == NULL)
    return NULL;
  SSH_ASSERT(x != NULL);

  ssh_mp_init(&p);
  ssh_mp_init(&g);
  ssh_mp_init(&y);
  dummy_rnd_state = ssh_random_allocate();

  cs = ssh_public_key_get_info(public_key,
                               SSH_PKF_PRIME_P, &p,
                               SSH_PKF_GENERATOR_G, &g,
                               SSH_PKF_PUBLIC_Y, &y,
                               SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    goto failed;

  cs = ssh_private_key_generate(dummy_rnd_state,
                                &key,
                                SSH_PGP_CANONICAL_ELGAMAL_NAME,
                                SSH_PKF_PRIME_P, &p,
                                SSH_PKF_GENERATOR_G, &g,
                                SSH_PKF_PUBLIC_Y, &y,
                                SSH_PKF_SECRET_X, x,
                                SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    {
      key = NULL;
      goto failed;
    }

 failed:
  ssh_mp_clear(&p);
  ssh_mp_clear(&g);
  ssh_mp_clear(&y);
  ssh_random_free(dummy_rnd_state);
  return key;
}

SshPrivateKey ssh_pgp_define_secret_dsa_key(SshPublicKey public_key,
                                            SshInt *x)
{
  SshInt p, q, g, y;
  SshPrivateKey key = NULL;
  SshCryptoStatus cs;
  SshRandomState dummy_rnd_state;

  if (public_key == NULL)
    return NULL;
  SSH_ASSERT(x != NULL);

  ssh_mp_init(&p);
  ssh_mp_init(&q);
  ssh_mp_init(&g);
  ssh_mp_init(&y);
  dummy_rnd_state = ssh_random_allocate();

  cs = ssh_public_key_get_info(public_key,
                               SSH_PKF_PRIME_P, &p,
                               SSH_PKF_PRIME_Q, &q,
                               SSH_PKF_GENERATOR_G, &g,
                               SSH_PKF_PUBLIC_Y, &y,
                               SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    goto failed;

  cs = ssh_private_key_generate(dummy_rnd_state,
                                &key,
                                SSH_PGP_CANONICAL_DSA_NAME,
                                SSH_PKF_PRIME_P, &p,
                                SSH_PKF_PRIME_Q, &q,
                                SSH_PKF_GENERATOR_G, &g,
                                SSH_PKF_PUBLIC_Y, &y,
                                SSH_PKF_SECRET_X, x,
                                SSH_PKF_END);
  if (cs != SSH_CRYPTO_OK)
    {
      key = NULL;
      goto failed;
    }

 failed:
  ssh_mp_clear(&p);
  ssh_mp_clear(&q);
  ssh_mp_clear(&g);
  ssh_mp_clear(&y);
  ssh_random_free(dummy_rnd_state);
  return key;
}

#endif /* WITH_PGP */
/* eof (pgp_key.c) */
