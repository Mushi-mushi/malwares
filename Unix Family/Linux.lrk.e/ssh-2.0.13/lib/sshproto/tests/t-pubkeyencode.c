/*

  t-pubkeyencode.c

  Author: Markku-Juhani Saarinen <mjos@ssh.fi>

  Copyright (c) 1996 SSH Communications Security, Finland
  All rights reserved

  Test the pubkeyencode functions. 

  */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "ssh2pubkeyencode.h"
#include "sshcipherlist.h"

#ifndef T_PUBKEYENCODE_ITERATIONS
#define T_PUBKEYENCODE_ITERATIONS 1
#endif /* T_PUBKEYENCODE_ITERATIONS */

const char plaintext[] = 
  "huuhaa jeejee superjee niks naks supertampax";

SshRandomState randseed;

void simple_test(char *keytype, int keybits)
{
  SshCryptoStatus code;
  SshPublicKey pubkey, pubkey2;
  SshPrivateKey privkey;
  unsigned char *blob1, *blob2;
  size_t len1, len2; 
  unsigned char *signature;
  size_t siglen, siglenr;

  /* generate a private key and a matching public key */

  if (ssh_private_key_generate(randseed, &privkey, keytype,
                               SSH_PKF_SIZE, keybits,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    ssh_fatal("simple_test: unable to generate %d - bit private key of type :"
              "\n%s\n", keybits, keytype);

  pubkey = ssh_private_key_derive_public_key(privkey);

  /* encode and decode the public key */

  if ((len1 = ssh_encode_pubkeyblob(pubkey, &blob1)) == 0)
    ssh_fatal("simple_test: ssh_encode_pubkeyblob() failed (1).");
 
  if ((pubkey2 = ssh_decode_pubkeyblob(blob1, len1)) == NULL)
    ssh_fatal("simple_test: ssh_decode_pubkeyblob() failed.");

  /* encode again to and compare blobs */
  if ((len2 = ssh_encode_pubkeyblob(pubkey2, &blob2)) == 0)
    ssh_fatal("simple_test: ssh_encode_pubkeyblob() failed (2).");

  if (len1 != len2)
    ssh_fatal("simple_test: blob length mismatch.");
  if (memcmp(blob1, blob2, len1) != 0)
    ssh_fatal("simple_test: blob's don't match.");

  /* sign something */

  siglen = ssh_private_key_max_signature_output_len(privkey);
  signature = ssh_xmalloc(siglen);
  
  code = ssh_private_key_sign(privkey, plaintext, strlen(plaintext),
                              signature, siglen, &siglenr, randseed);
  if (code != SSH_CRYPTO_OK)
    ssh_fatal("simple_test: ssh_private_key_sign() failed (%s).",
              ssh_crypto_status_message(code));

  /* ok, now verify the signature with our decoded public key */

  if (ssh_public_key_verify_signature(pubkey2, signature, siglenr,
                                      plaintext, strlen(plaintext) == FALSE))
    ssh_fatal("simple_test: signature verification failed.");
              
  ssh_xfree(blob1);
  ssh_xfree(blob2);
  ssh_xfree(signature);

  ssh_public_key_free(pubkey);
  ssh_public_key_free(pubkey2);
  ssh_private_key_free(privkey);
}


int main(int argc, char **argv)
{
  int i;

  randseed = ssh_random_allocate();
  for (i = 0; i < T_PUBKEYENCODE_ITERATIONS; i++)
    {
      simple_test(SSH_CRYPTO_RSA, 64 * i + 512); 
      simple_test(SSH_CRYPTO_DSS, 64 * i + 512);
    }
  ssh_random_free(randseed);

  return 0;
}
