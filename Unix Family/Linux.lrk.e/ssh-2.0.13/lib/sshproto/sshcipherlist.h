/*

  sshcipherlist.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Canonialize comma-separated cipher lists.

*/

#ifndef SSHCIPHERLIST_H
#define SSHCIPHERLIST_H

/* list of ciphers in secsh draft */
#define SSH_STD_CIPHERS \
        "3des-cbc,blowfish-cbc,arcfour,idea-cbc,cast128-cbc,twofish-cbc,none"

/*
   True if list `list' contains item `item'.
*/
Boolean ssh_cipher_list_contains(char *list, char *item);

/*
   Canonialize cipher names.  Unsupported algorithms are excluded
   and names of the supported ones are always replaced with the
   `native' one.
*/
char *ssh_cipher_list_canonialize(char *str);

/*
   Canonialize pubkey algorithm names.  Unsupported algorithms are 
   excluded and names of the supported ones are always replaced 
   with the `native' one.
*/
char *ssh_public_key_list_canonialize(char *str);

/*
   Canonialize hash algorithm names.  Unsupported algorithms are 
   excluded and names of the supported ones are always replaced 
   with the `native' one.
*/
char *ssh_hash_list_canonialize(char *str);

/* 
   Return a name list that contains items in list `original'
   so that items in list `excluded' are excluded. 
*/
char *ssh_cipher_list_exclude(char *original, char *excluded);

/*
   Convert between canonical cryptolib names and
   names in secsh draft.
 */
char *ssh_public_key_name_ssh_to_cryptolib(char *str);
char *ssh_public_key_name_cryptolib_to_ssh(char *str);

#endif /* SSHCIPHERLIST_H */

/* eof (sshcipherlist.h) */
