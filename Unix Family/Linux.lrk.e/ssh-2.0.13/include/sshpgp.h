/*

sshpgp.h

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Definitions for OpenPGP file format.

*/
/*
 * $Id: sshpgp.h,v 1.7 1999/04/07 15:14:56 tri Exp $
 * $Log: sshpgp.h,v $
 * $EndLog$
 */

#ifndef SSHPGP_H
#define SSHPGP_H

#ifdef WITH_PGP

#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshfilebuffer.h"

typedef struct SshPgpPacketRec *SshPgpPacket;

struct SshPgpPacketRec {
  unsigned char *data;
  size_t len;
  int type;
};

typedef struct SshPgpPublicKeyRec *SshPgpPublicKey;

struct SshPgpPublicKeyRec {
  SshUInt32 generation_time;
  SshUInt32 validity_time;
  SshUInt32 id_high;
  SshUInt32 id_low;
  char *fingerprint;
  int type;
  int version;
  SshPublicKey key;
};

typedef struct SshPgpSecretKeyRec *SshPgpSecretKey;

struct SshPgpSecretKeyRec {
  SshPgpPublicKey public_key;
  SshPrivateKey key;
  Boolean decryption_failed;
};

typedef struct SshPgpCipherRec *SshPgpCipher;

#define SSH_PGP_KEY_TYPE_RSA_PUBLIC                     1
#define SSH_PGP_KEY_TYPE_RSA_SECRET                     2
#define SSH_PGP_KEY_TYPE_DSA_PUBLIC                     3
#define SSH_PGP_KEY_TYPE_DSA_SECRET                     4
#define SSH_PGP_KEY_TYPE_ELGAMAL_PUBLIC                 5
#define SSH_PGP_KEY_TYPE_ELGAMAL_SECRET                 6

#define SSH_PGP_PK_ALGORITHM_RSA                        1
#define SSH_PGP_PK_ALGORITHM_RSA_ENCRYPT_ONLY           2
#define SSH_PGP_PK_ALGORITHM_RSA_SIGN_ONLY              3
#define SSH_PGP_PK_ALGORITHM_ELGAMAL_ENCRYPT_ONLY       16
#define SSH_PGP_PK_ALGORITHM_DSA                        17
#define SSH_PGP_PK_ALGORITHM_EC                         18
#define SSH_PGP_PK_ALGORITHM_ECDSA                      19
#define SSH_PGP_PK_ALGORITHM_ELGAMAL                    20
#define SSH_PGP_PK_ALGORITHM_DH                         21

#define SSH_PGP_SK_ALGORITHM_PLAIN                      0
#define SSH_PGP_SK_ALGORITHM_IDEA                       1
#define SSH_PGP_SK_ALGORITHM_3DES                       2
#define SSH_PGP_SK_ALGORITHM_CAST                       3
#define SSH_PGP_SK_ALGORITHM_BLOWFISH                   4
#define SSH_PGP_SK_ALGORITHM_SAFER                      5

#define SSH_PGP_HASH_ALGORITHM_MD5                      1
#define SSH_PGP_HASH_ALGORITHM_SHA1                     2
#define SSH_PGP_HASH_ALGORITHM_RIPEMD160                3
#define SSH_PGP_HASH_ALGORITHM_MD2                      5
#define SSH_PGP_HASH_ALGORITHM_TIGER192                 6
#define SSH_PGP_HASH_ALGORITHM_HAVAL_5_160              7

#define SSH_PGP_S2K_TYPE_SIMPLE                         0
#define SSH_PGP_S2K_TYPE_SALTED                         1
#define SSH_PGP_S2K_TYPE_ITERATED                       2 /* Non-std! */
#define SSH_PGP_S2K_TYPE_SALTED_ITERATED                3

#define SSH_PGP_PACKET_TYPE_ESK                         1
#define SSH_PGP_PACKET_TYPE_SIG                         2
#define SSH_PGP_PACKET_TYPE_CONVESK                     3
#define SSH_PGP_PACKET_TYPE_1PASSSIG                    4
#define SSH_PGP_PACKET_TYPE_SECKEY                      5
#define SSH_PGP_PACKET_TYPE_PUBKEY                      6
#define SSH_PGP_PACKET_TYPE_SECSUBKEY                   7
#define SSH_PGP_PACKET_TYPE_COMPRESSED                  8
#define SSH_PGP_PACKET_TYPE_CONVENTIONAL                9
#define SSH_PGP_PACKET_TYPE_MARKER                      10
#define SSH_PGP_PACKET_TYPE_LITERAL                     11
#define SSH_PGP_PACKET_TYPE_TRUST                       12
#define SSH_PGP_PACKET_TYPE_NAME                        13
#define SSH_PGP_PACKET_TYPE_PUBSUBKEY                   14
#define SSH_PGP_PACKET_TYPE_COMMENT                     16

#define SSH_PGP_SIG_TYPE_BINARY_DOCUMENT                0x00
#define SSH_PGP_SIG_TYPE_TEXT_DOCUMENT                  0x01
#define SSH_PGP_SIG_TYPE_STANDALONE                     0x02
#define SSH_PGP_SIG_TYPE_UID_CERT_GENERIC               0x10
#define SSH_PGP_SIG_TYPE_UID_CERT_PERSONA               0x11
#define SSH_PGP_SIG_TYPE_UID_CERT_CASUAL                0x12
#define SSH_PGP_SIG_TYPE_UID_CERT_POSITIVE              0x13
#define SSH_PGP_SIG_TYPE_SUBKEY                         0x18
#define SSH_PGP_SIG_TYPE_KEY                            0x1f
#define SSH_PGP_SIG_TYPE_KEY_REVOCATION                 0x20
#define SSH_PGP_SIG_TYPE_SUBKEY_REVOCATION              0x28
#define SSH_PGP_SIG_TYPE_CERT_REVOCATION                0x30
#define SSH_PGP_SIG_TYPE_TIMESTAMP                      0x40

#define SSH_PGP_CANONICAL_RSA_NAME \
                "if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}"
#define SSH_PGP_CANONICAL_ELGAMAL_NAME \
                "dl-modp{encrypt{elgamal-random-none}}"
#define SSH_PGP_CANONICAL_DSA_NAME \
                "dl-modp{sign{dsa-nist-sha1}}"

/* pgp_file.c */
Boolean ssh_pgp_read_packet(SshFileBuffer *filebuf, SshPgpPacket *packet);
Boolean ssh_pgp_next_packet_type(SshFileBuffer *filebuf, int *type);

/* pgp_gen.c */
const char *ssh_pgp_canonical_cipher_name(int cipher);
const char *ssh_pgp_canonical_hash_name(int hash);
const char *ssh_pgp_packet_type_str(int type);
void ssh_pgp_packet_free(SshPgpPacket packet);

/* pgp_s2k.c */
Boolean ssh_pgp_s2k(const char *passphrase, 
                    int s2k_type,
                    unsigned char *s2k_salt,
                    int s2k_count_byte,
                    int hash_algorithm,
                    unsigned char *key_buf,
                    int key_buf_len);

/* pgp_keydb.c */
Boolean ssh_pgp_find_public_key_with_name(SshFileBuffer *filebuf, 
                                          const char *name,
                                          Boolean exact,
                                          SshPgpPacket *packet,
                                          char **comment);

Boolean ssh_pgp_find_public_key_with_key_id(SshFileBuffer *filebuf, 
                                            SshUInt32 key_id,
                                            SshPgpPacket *packet,
                                            char **comment);

Boolean ssh_pgp_find_public_key_with_fingerprint(SshFileBuffer *filebuf, 
                                                 const char *fingerprint,
                                                 SshPgpPacket *packet,
                                                 char **comment);

Boolean ssh_pgp_find_secret_key_with_name(SshFileBuffer *filebuf, 
                                          const char *name,
                                          Boolean exact,
                                          SshPgpPacket *packet,
                                          char **comment);

Boolean ssh_pgp_find_secret_key_with_key_id(SshFileBuffer *filebuf, 
                                            SshUInt32 key_id,
                                            SshPgpPacket *packet,
                                            char **comment);

Boolean ssh_pgp_find_secret_key_with_fingerprint(SshFileBuffer *filebuf, 
                                                 const char *fingerprint,
                                                 SshPgpPacket *packet,
                                                 char **comment);
/* pgp_packet.c */
char *ssh_pgp_packet_name(SshPgpPacket packet);

/* pgp_key.c */
size_t ssh_pgp_public_key_decode(const unsigned char *data, 
                                 size_t len, 
                                 SshPgpPublicKey *key);

void ssh_pgp_public_key_free(SshPgpPublicKey key);

size_t ssh_pgp_secret_key_decode(const unsigned char *data, 
                                 size_t len, 
                                 SshPgpSecretKey *key);

size_t ssh_pgp_secret_key_decode_with_passphrase(const unsigned char *data, 
                                                 size_t len, 
                                                 const char *passphrase,
                                                 SshPgpSecretKey *key);

void ssh_pgp_secret_key_free(SshPgpSecretKey key);

/* pgp_cipher.c */
SshCryptoStatus ssh_pgp_cipher_allocate(int type,
                                        const char *key_str,
                                        int s2k_type,
                                        int s2k_hash,
                                        int s2k_count,
                                        unsigned char *s2k_salt,
                                        Boolean for_encryption,
                                        SshPgpCipher *cipher);

void ssh_pgp_cipher_transform(SshPgpCipher cipher,
                              unsigned char *dest,
                              const unsigned char *src,
                              size_t len);

void ssh_pgp_cipher_resync(SshPgpCipher cipher);

void ssh_pgp_cipher_free(SshPgpCipher cipher);

#endif /* WITH_PGP */

#endif /* ! SSHPGP_H */

/* eof (sshpgp.h) */
