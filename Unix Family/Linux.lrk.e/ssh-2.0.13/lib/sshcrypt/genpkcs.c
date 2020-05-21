/*

  genpkcs.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jun  2 18:43:45 1997 [mkojo]

  Interface code for public key cryptosystems.

    TODO:

      - implement generic code for:

        One-way authenticated key exchange
        Two-way authenticated key exchange
        Menezes-Qu-Vanstone protocol
        Unified Diffie-Hellman key exchange

      - more exact errors (and debug information) of vararg list errors ;)
        
      - add pk_group_randomizer_count

      - add pk_public_key_type_encrypt_capability
      - add pk_public_key_type_sign_capability
      - add pk_public_key_type_dh_capability

    NEW IDEAS:

      Current naming follows
      dl-modp{dh{plain}},
      however, this could be transformed into
      dl-modp{dh,sign{rsa-pkcs1-md5}},
      because diffie-hellman does not have a large number of
      possible parameters, indeed, it is almost always the plain
      version. Thus it could be mapped to dl-modp{dh,...} etc.
      
      */

/*
 * $Id: genpkcs.c,v 1.46 1999/04/29 13:38:10 huima Exp $
 * $Log: genpkcs.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshbuffer.h"
#include "sshbufaux.h"
#include "md5.h"
#include "sha.h"
#include "sshgetput.h"
#include "dlglue.h"
#include "sshencode.h"
#include "namelist.h"

/* Magic numbers used for validy checks in SSH public key
   exported octet formats. */
#define SSH_PK_GROUP_RANDOMIZER_MAGIC 0x4c9356fe
#define SSH_PK_GROUP_MAGIC            0x89578271
#define SSH_PUBLIC_KEY_MAGIC          0x65c8b28a
#define SSH_PRIVATE_KEY_MAGIC         0x3f6ff9eb

/************************************************************************/

/* SSH public key methods, that are visible through the generic interface,
   are defined here. Motivation for this system is to support
   both discrete logarithm (dl) and integer factorization (if) based
   systems with equal ease.

   We represent a public key cryptosystem with 

   key types:

     which stand for the underlying operation. For example, with
     RSA (if-modn) we have a different key type than with
     Diffie-Hellman (dl-modp). Note that key types are the highest
     structure of the public key cryptosystem. Also a public/private/group
     must be of some key type (although not neccessary either of dl-modp or
     if-modn).

     Currently supported key types are:

       if-modn
       dl-modp
       ec-modp
       ec-gf2n

     it is also possible to add e.g. 
       
       lu-modp (Lucas functions over finite field (mod p))

     Key types are defined as large structures containing few function
     pointers. This style is used in all algorithm definitions here.

     
   schemes:

     which stand for some specific method or algorithm. Such as
     RSA or Diffie-Hellman. Note that there are possibly many variations
     of one algorithm, thus exact naming of an algorithm is a must. And
     obviously all algorithms must have unique name.

     We have divided schemes into various scheme types:

       sign    = signature schemes
       encrypt = encryption schemes
       dh      = diffie-hellman schemes (there seems to be just one)
       ...

     basic criteria is to divide into smallest possible operation, allowing
     us to handle scheme types separately. 
     
     Following algorithms are supported (as an example):

       if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}},
       dl-modp{sign{dsa-nist-sha1}}
       
     Naming format is 

       key-type{scheme-type{algorithm-name},...}

     which can be listed in a comma separated list. Functions that handle
     this name tree can be found in namelist.h.

     Schemes are defined as large structures (of many different types)
     containing few function pointers. Currently defined scheme types are

       SshPkSignature
       SshPkEncryption
       SshPkDiffieHellman
       SshPkUnifiedDiffieHellman

     more should be added in future. Clearly adding more scheme types
     is possible, although not very easy. We see no need to add many
     new scheme types although following have been considered

       SshPkOneWayAuthentication
       SshPkTwoWayAuthentication
       SshPkMenezedQuVanstoneProtocol

     (although those might not be the actual names to be used.)

     
   actions:

     in attempt to make this file atleast partially readable actions have
     been introduced. These contain information of scheme types and
     "actions" allowed to be performed in generation of keys/groups.

     
   */
   

/* Following flag is used with actions to indicate that

     - action is to be ignored.
     - action can be used to extract or place information into
       keys structures.
     - indicate that action leads to scheme information.
     - optimization.
     - indicates that action leads to no further information.
     - defines for which type (private/public/group) should this
       action be used. 

   */

typedef unsigned int SshPkFlag;
#define SSH_PK_FLAG_IGNORE       0
#define SSH_PK_FLAG_SPECIAL      1
#define SSH_PK_FLAG_SCHEME       2
#define SSH_PK_FLAG_LIST         4
#define SSH_PK_FLAG_KEY_TYPE     8
#define SSH_PK_FLAG_WRAPPED      16
#define SSH_PK_FLAG_PRIVATE_KEY  32
#define SSH_PK_FLAG_PUBLIC_KEY   64
#define SSH_PK_FLAG_PK_GROUP     128

/* Schemes thought to be supported in future. We might want 
   to leave something out or implement others. */

typedef enum
{
  /* Invalid scheme */
  SSH_PK_SCHEME_NONE,
  
  /* Valid schemes */
  SSH_PK_SCHEME_SIGN,
  SSH_PK_SCHEME_ENCRYPT,
  SSH_PK_SCHEME_DH,
  /* SSH_PK_SCHEME_UDH, */
  SSH_PK_SCHEME_OWA,
  SSH_PK_SCHEME_TWA,
  SSH_PK_SCHEME_MQV
} SshPkSchemeFlag;


/* Here we define a simple name, that can be used to indicate that a
   name like
     dl-modp{mymethod}
   is also valid. This is expanded to
     dl-modp{mymethod{plain}}
   and thus you need to name your actual scheme as plain within you
   group of many methods. If you don't want to do that, you just have
   to bear with
     dl-modp{mymethod{myname}}. */
#define SSH_PK_USUAL_NAME "plain"

/* Action definitions.

   Action, as a term, is here used to mean one object in an "action list".
   Action can be used to either just flag some general operation, or to
   start-up a function with arguments from vararg list. Further the
   action can be tied together for "action-list" which can used for
   a more appropriately doing lots of things.

   Current implementation assumes of action lists:

   * includes init and make functions, currently these will be found
     not in action lists but in key type definitions. These are used
     to create the temporary context where inputs will be
     stacked. Then when vararg list is fully traversed, make is
     invoked to generate a context which will be included to private
     keys and pk groups.

   * scheme lists, these are included into action lists to "ease"
     maintaining.

   * special operations, which use those temporary contexts, add
     information to the context gotten from vararg list.
   
 */

typedef struct 
{
  /* Generic information about this action. */

  /* Type of this action. */
  SshPkFormat format;
  /* Name of this action if scheme type. */
  const char *scheme_class;
  /* Flags to define what this action contains and where to use it. */
  SshPkFlag flags;

  /* Scheme information */
  SshPkSchemeFlag scheme_flag;
  /* Regrettably we are forced to use void's here. Thus care should be
     exercised in writing actions. */
  size_t type_size;
  const void *type;

  /* Action functions. Functions to put and take information form
     contexts.

     Main idea is, as explained before, in generating either private key
     or pk group, to generate a temporary context to where action_put
     can add information. This function will not be used elsewhere.

     action_get on the otherhand will work with the actual
     private/public/group contexts. That is it is allowed to take out
     even "secret" information.
     */
  unsigned int (*action_put)(void *context, va_list *ap,
                             void *input_context, 
                             SshPkFormat format);
  unsigned int (*action_get)(void *context, va_list *ap,
                             void **output_context,
                             SshPkFormat format);
} SshPkAction;

/* Header for all scheme structures. Casts to this will be performed while
   seeking and calling special initialization routines (if present). */

typedef struct
{
  /* Unique name (among same scheme types). */
  
  const char *name;

  /* Special init function, called if not set to NULL. Main purpose is
     to tell the action_make routine (found in key type definitions)
     that such and such scheme will probably use it. However, not all
     schemes need to have this function, only if parameters that are
     to be generated should be of certain form. Such an example is DSA
     signature method, which needs (to be compatible with the
     standard) parameters of some predefined form.

     However, using this isn't all neccessary and action_make should use
     this information only if no other specific parameter or key
     generation information has been given. Also action_make should
     do something even if no scheme given any specific information (e.g.
     use some default values).  */
  void (*action_scheme)(void *context);
} SshPkGen;

/* Following structure definitions are based on observation that the group
   (or parameters) of the field where public key method works should be
   the basis (or lowest) of public key and private key structures. Although
   here we've done it the easy way and have them all in same.

   But nevertheless, over group we can build cryptosystem having private and
   public keys. Over these keys we can hopefully build schemes, and these
   schemes can be divided in to many classes. 

   Here we've chosen to represent also all key exchange
   schemes as "schemes". This might not be always the best way, but some
   times, like with diffie-hellman and some other basic schemes this
   is quite nice.

   The structure here used to represent public key methods is for ease
   of maintaining, which is of very importance, ease of adding new
   schemes, reasonable efficiency. Probably this way we cannot
   represent all methods, but atleast those that are the most
   obvious.    
   */

/* Scheme structure definition. 

   NOTE! All following structures MUST start with const char *name, this
   is assumed in the following code. */

/* Signature schemes */

typedef struct
{
  /* Names can contain any ascii characters but ",{}" which are used to
     separate them in namelists. All signature algorithm names should
     be unique. 
     */
       
  const char *name;

  void (*action_scheme)(void *context);
  
  /* Hash function to use with this scheme. */

  const SshHashDef *hash_def;
  
  /* Maximum lengths for signature output/input. */
  size_t (*private_key_max_signature_input_len)(const void *private_key);
  size_t
  (*private_key_max_signature_output_len)(const void *private_key);
  
  Boolean (*public_key_verify)(const void *public_key,
                               const unsigned char *signature,
                               size_t signature_len,
                               Boolean need_hashing,
                               const unsigned char *data,
                               size_t data_len,
                               const SshHashDef *hash_def);

  Boolean (*private_key_sign)(const void *private_key,
                              Boolean need_hashing,
                              const unsigned char *data,
                              size_t data_len,
                              unsigned char *signature_buffer,
                              size_t ssh_buffer_len,
                              size_t *signature_length_return,
                              SshRandomState state,
                              const SshHashDef *hash_def);
} SshPkSignature;

/* Encryption schemes */

typedef struct
{
  /* Encryption scheme names should be unique and follow if possible
     our naming policy. */
  
  const char *name;

  void (*action_scheme)(void *context);
  
  /* Hash function for padding/encryption. In most cases encryption
     functions do not need hash function, although some recent methods
     offer them. */
  
  const SshHashDef *hash_def;
  
  /* Decryption input/output maximum buffer lengths. */
  size_t (*private_key_max_decrypt_input_len)(const void *private_key);
  size_t (*private_key_max_decrypt_output_len)(const void *private_key);

  /* Private key decryption. */
  Boolean (*private_key_decrypt)(const void *private_key,
                                 const unsigned char *ciphertext,
                                 size_t ciphertext_len,
                                 unsigned char *plaintext_buffer,
                                 size_t ssh_buffer_len,
                                 size_t *plaintext_length_return,
                                 const SshHashDef *hash_def);

  /* Maximum encryption output/input buffer lengths. */
  size_t (*public_key_max_encrypt_input_len)(const void *public_key);
  size_t (*public_key_max_encrypt_output_len)(const void *public_key);

  /* Encryption with the public key. */
  Boolean (*public_key_encrypt)(const void *public_key,
                                const unsigned char *plaintext,
                                size_t plaintext_len,
                                unsigned char *ciphertext_buffer,
                                size_t ssh_buffer_len,
                                size_t *ciphertext_len_return,
                                SshRandomState random_state,
                                const SshHashDef *hash_def);
} SshPkEncryption;

/* Diffie-Hellman */

typedef struct
{
  /* Diffie-Hellman type name. */
  const char *name;

  void (*action_scheme)(void *context);
  
  /* Diffie-Hellman internal interface definitions */

  size_t (*diffie_hellman_exchange_max_length)(const void *pk_group);
  size_t (*diffie_hellman_secret_value_max_length)(const void *pk_group);
  
  Boolean (*diffie_hellman_setup)(void *pk_group,
                                  void **dh_extra,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  size_t *return_length,
                                  SshRandomState state);

  Boolean (*diffie_hellman_agree)(void *pk_group,
                                  void *dh_extra,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  unsigned char *secret_value_buffer,
                                  size_t secret_value_buffer_length,
                                  size_t *return_length);

  /* Unified Diffie-Hellman protocol as suggested by
     Don Johnson at P1363 meeting May 15-16 1997. */
  
  /* Diffie-Hellman hides within Unified approach! */
  size_t (*udh_secret_value_max_length)(const void *pk_group);
  Boolean (*udh_agree)(const void *public_key,
                       const void *private_key,
                       void *dh_extra,
                       unsigned char *exchange_buffer,
                       size_t exchange_length,
                       unsigned char *secret_value_buffer,
                       size_t secret_value_length,
                       size_t *return_length);
  
} SshPkDiffieHellman;

#if 0
typedef struct
{ 
  const char *name;
  
  void (*action_scheme)(void *context);
  
  /* Diffie-Hellman internal interface definitions */

  size_t (*udh_exchange_max_length)(const void *pk_group);
  
  Boolean (*udh_setup)(void *pk_group,
                       void **dh_extra,
                       unsigned char *exchange_buffer,
                       size_t exchange_buffer_length,
                       size_t *return_length,
                       SshRandomState state);
  
  
} SshPkUnifiedDiffieHellman;
#endif

#if 1
/* XXX Following scheme definitions are used and not yet finished. */

/* One way authentication schemes */

typedef struct
{
  /* One-Way Authenticated key exchange protocol, is designed for SSH. Here
     are few variations. Names aren't standardized, so use any name that is
     unique. */
  const char *name;
  
  void (*action_scheme)(void *context);
  
  /* We need a hash function, these schemes are based on Diffie-Hellman and
     signature schemes. */
  SshHashDef *hash_def;

  /* OWA interface. Needs just few functions. */
  
} SshPkOneWayAuth;


/* Menezes-Qu-Vanstone protocol */

typedef struct
{
  const char *name;

  void (*action_scheme)(void *context);
  
} SshPkMQV;

/* Two way authentication schemes */

typedef struct
{
  /* Two-Way authenticated key exchange protocol, is extended OWA. Few
     variations should exist. Names should be just unique. */
  const char *name;

  void (*action_scheme)(void *context);
  
  unsigned int hash_digest_length;
  void (*hash_of_buffer)(unsigned char *digest, unsigned char *date,
                         size_t len);
} SshPkTwoWayAuth;

/* More schemes? */

#endif
                        
/* General main key type structure. This structure defines the most important
   part, the handling of internal key/group contexts. */

typedef struct
{
  /* Name for key. Keys are named/typed as follows:

       if-modn    for RSA etc.
       dl-modp    for DSA, ElGamal etc.
       ec-modp    for ECDSA, ECElGamal etc.
       ec-gf2n    for ECDSA, etc.
     */
  const char *name;

  /* Special actions, for key management. I.e. things like inserting
     parameters, fixing exponent etc. */
  const SshPkAction *action_list;

  /* Group functions */

  /* Initialization and make. */
  void *(*pk_group_action_init)(SshRandomState state);
  void *(*pk_group_action_make)(void *context);
  void (*pk_group_action_free)(void *context);
  
  Boolean (*pk_group_import)(const unsigned char *buf,
                             size_t length,
                             void **pk_group);
  Boolean (*pk_group_export)(const void *pk_group,
                             unsigned char **buf,
                             size_t *length_return);
  void (*pk_group_free)(void *pk_group);
  void (*pk_group_copy)(void *op_src, void **op_dest);
  char *(*pk_group_get_predefined_groups)(void);
  
  /* Randomizer handling. */
  unsigned int (*pk_group_count_randomizers)(void *pk_group);
  Boolean (*pk_group_generate_randomizer)(void *pk_group,
                                          SshRandomState state);
  Boolean (*pk_group_export_randomizer)(void *pk_group,
                                        unsigned char **buf,
                                        size_t *length_return);
  Boolean (*pk_group_import_randomizer)(void *pk_group,
                                        unsigned char *buf,
                                        size_t length);

  /* Key functions */

  /* Initialization (definition) and make. Note that it makes no
     sense in generating new public key so we don't give random state
     here. */
  void *(*public_key_action_init)(void);
  void *(*public_key_action_make)(void *context);
  void (*public_key_action_free)(void *context);

  /* Public key blob import and export function interfaces. */
  Boolean (*public_key_import)(const unsigned char *buf,
                               size_t len,
                               void **public_key);
  Boolean (*public_key_export)(const void *public_key,
                               unsigned char **buf,
                               size_t *length_return);
  /* Removal of public key from memory. */
  void (*public_key_free)(void *public_key);

  void (*public_key_copy)(void *op_src, void **op_dest);

  void (*public_key_derive_pk_group)(void *public_key,
                                     void **pk_group);


  /* Private key action initialization and key generation routines. */
  void *(*private_key_action_init)(SshRandomState state);
  void *(*private_key_action_make)(void *context);
  void (*private_key_action_free)(void *context);
    
  /* Import and export of private key blobs. */
  Boolean (*private_key_import)(const unsigned char *buf,
                                size_t len,
                                void **private_key);
  Boolean (*private_key_export)(const void *private_key,
                                unsigned char **buf,
                                size_t *length_return);
  /* Removal of the private key from memory. */
  void (*private_key_free)(void *private_key);
  /* Deriving public key from private key. */
  void (*private_key_derive_public_key)(const void *private_key,
                                        void **public_key);

  void (*private_key_copy)(void *op_src, void **op_dest);

  void (*private_key_derive_pk_group)(void *private_key,
                                      void **pk_group);
  
  /* More to come... */
} SshPkType;

/* Context that contain all information especially needed in 
   the generic code. */

struct SshPkGroupRec
{
  /* General information (which are supported with just parameters) */
  const SshPkType *type;

  /* Scheme supported. */
  const SshPkDiffieHellman *diffie_hellman;
  
  /* Special parameter information / key dependend */
  void *context;
};

struct SshPublicKeyRec
{
  /* General information */
  const SshPkType *type;

  /* Schemes */
  const SshPkSignature *signature;
  const SshPkEncryption *encryption;
  const SshPkDiffieHellman *diffie_hellman;
  /* XXX const SshPkUnifiedDiffieHellman *unified_diffie_hellman; */
  const SshPkOneWayAuth *one_way_auth;
  const SshPkTwoWayAuth *two_way_auth;
  const SshPkMQV *mqv;

  /* Special information / key dependend */
  void *context;
};

struct SshPrivateKeyRec
{
  /* General information */
  const SshPkType *type;

  /* Schemes */
  const SshPkSignature *signature;
  const SshPkEncryption *encryption;
  const SshPkDiffieHellman *diffie_hellman;
  /* const SshPkUnifiedDiffieHellman *unified_diffie_hellman; */
  const SshPkOneWayAuth *one_way_auth;
  const SshPkTwoWayAuth *two_way_auth;
  const SshPkMQV *mqv;

  /* Special information / key dependend */
  void *context;

  
};

/* Definitions of schemes. Those who wish to add more algorithms should
   study style used here. */

#if 0
const SshPkSignature ssh_device_signature_schemes[] =
{
  { "pkcs11", NULL,
    NULL,
    ssh_pkcs11_private_key_max_signature_input_len, 
    ssh_pkcs11_private_key_max_signature_output_len,
    ssh_pkcs11_public_key_verify,
    ssh_pkcs11_private_key_sign },
  { NULL }
};
#endif


/* Table of all supported signature schemes for dl-modp keys. */

const SshPkSignature ssh_dl_modp_signature_schemes[] =
{
  { "dsa-nist-sha1",
    ssh_dlp_dsa_nist,
    &ssh_hash_sha_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    ssh_dlp_dsa_private_key_sign
  },
  { NULL }
};

/* Table of all supported encryption schemes for dl-modp keys. */

const SshPkEncryption ssh_dl_modp_encryption_schemes[] =
{
#if 0
  { "elgamal-none-none",
    NULL,
    NULL,
    ssh_dlp_elgamal_private_key_max_decrypt_input_len,
    ssh_dlp_elgamal_private_key_max_decrypt_output_len,
    ssh_dlp_elgamal_private_key_decrypt,
    ssh_dlp_elgamal_public_key_max_encrypt_input_len,
    ssh_dlp_elgamal_public_key_max_encrypt_output_len,
    ssh_dlp_elgamal_public_key_encrypt },
#endif
  { NULL }
};

/* Table of all supported diffie-hellman schemes for dl-modp keys. */

const SshPkDiffieHellman ssh_dl_modp_diffie_hellman_schemes[] =
{
  { "plain",
    NULL,
    ssh_dlp_diffie_hellman_exchange_length,
    ssh_dlp_diffie_hellman_shared_secret_length,
    ssh_dlp_diffie_hellman_generate,
    ssh_dlp_diffie_hellman_final,
    ssh_dlp_unified_diffie_hellman_shared_secret_length,
    ssh_dlp_unified_diffie_hellman_final
  },
  { NULL },
};



/* Action lists. These lists contain most information about generation of
   private keys, and parameters. */


/* DLP special actions. */

const SshPkAction ssh_pk_dl_modp_actions[] =
{
  /* key type */
  { SSH_PKF_KEY_TYPE, NULL, 
    SSH_PK_FLAG_KEY_TYPE | SSH_PK_FLAG_PRIVATE_KEY |
    SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_PK_GROUP,
    SSH_PK_SCHEME_NONE, 0, NULL },
  
  /* Schemes */
  { SSH_PKF_SIGN, "sign", 
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY,
    SSH_PK_SCHEME_SIGN,
    sizeof(SshPkSignature),
    ssh_dl_modp_signature_schemes, NULL },

#if 0
  { SSH_PKF_ENCRYPT, "encrypt",
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY,
    SSH_PK_SCHEME_ENCRYPT,
    sizeof(SshPkEncryption),
    ssh_dl_modp_encryption_schemes, NULL },
#endif
  
  { SSH_PKF_DH, "dh", 
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY |
    SSH_PK_FLAG_PK_GROUP,
    SSH_PK_SCHEME_DH,
    sizeof(SshPkDiffieHellman),
    ssh_dl_modp_diffie_hellman_schemes, NULL },
  
#if 0
  /* XXX To be implemented. */
  
  { SSH_PKF_OWA, "owa", 
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY,
    SSH_PK_SCHEME_OWA,
    sizeof(SshPkOneWayAuth),
    ssh_dl_modp_owa_schemes,        NULL },
  
  { SSH_PKF_TWA, "twa", 
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY,
    SSH_PK_SCHEME_TWA,
    sizeof(SshPkTwoWayAuth),
    ssh_dl_modp_twa_schemes,        NULL },

  { SSH_PKF_MQV, "mqv", 
    SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_PRIVATE_KEY | SSH_PK_FLAG_PUBLIC_KEY,
    SSH_PK_SCHEME_MQV,
    sizeof(SshPkMQV),
    ssh_dl_modp_mqv_schemes,        NULL },
#endif
  
  /* Handling of keys and parameters. */

  /* prime-p (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_P, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },
  
  { SSH_PKF_PRIME_P, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },
  
  { SSH_PKF_PRIME_P, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  /* generator-g (private_key, public_key, pk_group versions) */
  { SSH_PKF_GENERATOR_G, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_GENERATOR_G, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  { SSH_PKF_GENERATOR_G, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  /* prime-q (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_Q, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },
  
  { SSH_PKF_PRIME_Q, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL, 
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },
  
  { SSH_PKF_PRIME_Q, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  /* secret-x (private_key) */
  { SSH_PKF_SECRET_X, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  /* public-y (private_key, public_key) */
  { SSH_PKF_PUBLIC_Y, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },
  
  { SSH_PKF_PUBLIC_Y, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },
  
  /* size (private_key, public_key, pk_group) */
  { SSH_PKF_SIZE, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_SIZE, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  { SSH_PKF_SIZE, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  /* randomizer entropy (private_key, public_key, pk_group) */
  { SSH_PKF_RANDOMIZER_ENTROPY, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_RANDOMIZER_ENTROPY, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  { SSH_PKF_RANDOMIZER_ENTROPY, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  /* Predefined group. */
  { SSH_PKF_PREDEFINED_GROUP, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PRIVATE_KEY,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },
  
  { SSH_PKF_PREDEFINED_GROUP, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PUBLIC_KEY | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },
  
  { SSH_PKF_PREDEFINED_GROUP, NULL, 
    SSH_PK_FLAG_SPECIAL | SSH_PK_FLAG_PK_GROUP | SSH_PK_FLAG_LIST,
    SSH_PK_SCHEME_NONE, 0,
    NULL,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },
  
  /* End of list. */
  { SSH_PKF_END }
};



/* more actions to come... */

/* Table of all supported key types. */

const SshPkType ssh_key_types[] =
{
  /* Key type for discrete log based systems. */
  { "dl-modp",
    ssh_pk_dl_modp_actions,

    /* Basic group operations. */
    ssh_dlp_action_init,
    ssh_dlp_param_action_make,
    ssh_dlp_action_free,

    ssh_dlp_param_import,
    ssh_dlp_param_export,
    ssh_dlp_param_free,
    ssh_dlp_param_copy,
    ssh_dlp_param_get_predefined_groups,

    /* Randomizer generation. */
    ssh_dlp_param_count_randomizers,
    ssh_dlp_param_generate_randomizer,
    ssh_dlp_param_export_randomizer,
    ssh_dlp_param_import_randomizer,

    /* Public key operations. */
    ssh_dlp_action_public_key_init,
    ssh_dlp_public_key_action_make,
    ssh_dlp_action_free,
    
    ssh_dlp_public_key_import,
    ssh_dlp_public_key_export,
    ssh_dlp_public_key_free,
    ssh_dlp_public_key_copy,
    ssh_dlp_public_key_derive_param,

    /* Private key operations. */
    ssh_dlp_action_init,
    ssh_dlp_private_key_action_make,
    ssh_dlp_action_free,

    ssh_dlp_private_key_import,
    ssh_dlp_private_key_export,
    ssh_dlp_private_key_free,
    ssh_dlp_private_key_derive_public_key,
    ssh_dlp_private_key_copy,
    ssh_dlp_private_key_derive_param
  },    
  { NULL }
};

/************************************************************************/


/* Next: genpkcs.c functions ;) */

/* Find action with FLAG_SCHEME set on and matching given identifier. This
   is used when parsing names. */

const SshPkAction *ssh_pk_find_scheme_action(const SshPkAction *list,
                                             const char *identifier,
                                             const SshPkFlag given_flags)
{
  unsigned int i;
  SshPkFlag flags = given_flags | SSH_PK_FLAG_SCHEME;
  
  for (i = 0; list[i].format != SSH_PKF_END; i++)
    {
      if ((list[i].flags & flags) == flags)
        {
          /* Check for optimization. */
          if (strcmp(list[i].scheme_class, identifier) == 0)
            return &list[i];
        }
    }
  /* Failed to find a match. */
  return NULL;
}

/* Search from action list an entry that has atleast 'flags' on. */

const SshPkAction *ssh_pk_find_action(SshPkFormat format,
                                      const SshPkAction *list,
                                      const SshPkFlag flags)
{
  unsigned int i;
  Boolean prev = FALSE;

  for (i = 0; list[i].format != SSH_PKF_END; i++)
    {
      /* Check for optimization. */
      if (!((list[i].flags & SSH_PK_FLAG_LIST) && prev))
        {
          if (list[i].format == format)
            prev = TRUE;
          else
            continue;
        }

      /* Check whether flags match. */
      if ((list[i].flags & flags) == flags)
        {
          /* Found a correct match (because they are assumed to be unique
             this must be correct). */

          return &list[i];
        }
    }
  /* Failed to find a match. */
  return NULL;
}

/* Generic search for tables where the first element is const char *.
   How else can one do this? */
   
void *ssh_pk_find_generic(const char *name, const void *list, size_t msize)
{
  const unsigned char *buf = list;
  const char *buf_name;
  unsigned int i;

  /* buf[i] points to start of a structure (which size is msize), buf_name
     is set to the const char * from start of the buf[i]. */
  for (i = 0; (buf_name = *((const char **)(buf + i))) ; i += msize)
    {
      if (strcmp(buf_name, name) == 0)
        {
          return (void *)(buf + i);
        }
    }
  return NULL;
}

/* Advance generically in scheme tables. Returns the first const char *
   pointer from scheme table (i.e. the name). */
const char *ssh_pk_next_generic(const void **list, size_t msize)
{
  const char *name = *((const char **)*list);
  *list = (void *)((unsigned char *)*list + msize);
  return name;
}

/* Routines for getting scheme names from private keys and public keys.
   No other information is reasonable to expect to be gotten from
   schemes, although one could think getting descriptions etc...
   */

SshCryptoStatus ssh_private_key_get_scheme_name(SshPrivateKey key,
                                                const char **name,
                                                SshPkSchemeFlag flag)
{
  switch (flag)
    {
    case SSH_PK_SCHEME_SIGN:
      *name = key->signature->name;
      break;
    case SSH_PK_SCHEME_ENCRYPT:
      *name = key->encryption->name;
      break;
    case SSH_PK_SCHEME_DH:
      *name = key->diffie_hellman->name;
      break;
      /*XXX 
    case SSH_PK_SCHEME_UDH:
      *name = key->unified_diffie_hellman->name;
      break;*/
    case SSH_PK_SCHEME_OWA:
      *name = key->one_way_auth->name;
      break;
    case SSH_PK_SCHEME_TWA:
      *name = key->two_way_auth->name;
      break;
    case SSH_PK_SCHEME_MQV:
      *name = key->mqv->name;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_public_key_get_scheme_name(SshPublicKey key,
                                               const char **name,
                                               SshPkSchemeFlag flag)
{
  switch (flag)
    {
    case SSH_PK_SCHEME_SIGN:
      *name = key->signature->name;
      break;
    case SSH_PK_SCHEME_ENCRYPT:
      *name = key->encryption->name;
      break;
    case SSH_PK_SCHEME_DH:
      *name = key->diffie_hellman->name;
      break;
      /*XXX 
    case SSH_PK_SCHEME_UDH:
      *name = key->unified_diffie_hellman->name;
      break;*/
    case SSH_PK_SCHEME_OWA:
      *name = key->one_way_auth->name;
      break;
    case SSH_PK_SCHEME_TWA:
      *name = key->two_way_auth->name;
      break;
    case SSH_PK_SCHEME_MQV:
      *name = key->mqv->name;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
  
}

/* Helpful function. */
SshNameNode ssh_pk_add_nnode(SshNameTree tree, SshNameNode node,
                             const char *scheme_type,
                             const char *scheme_identifier,
                             Boolean *flag)
{
  SshNameNode temp;
  
  if (*flag)
    {
      temp = ssh_ntree_add_next(tree, node,
                                scheme_type);
    }
  else
    {
      temp = ssh_ntree_add_child(tree, node,
                                 scheme_type);
      *flag = TRUE;
    }
  ssh_ntree_add_child(tree, temp,
                      scheme_identifier);
  return temp;
}

/* Generate the full name of a particular private key. */
DLLEXPORT char * DLLCALLCONV
ssh_private_key_name(SshPrivateKey key)
{
  SshNameTree tree;
  SshNameNode node;
  char *tmp;
  Boolean flag = FALSE;
  
  ssh_ntree_allocate(&tree);

  node = ssh_ntree_add_child(tree, NULL,
                             key->type->name);
  if (key->signature)
    node = ssh_pk_add_nnode(tree, node, "sign", key->signature->name, &flag);
  if (key->encryption)
    node = ssh_pk_add_nnode(tree, node, "encrypt", key->encryption->name,
                            &flag);
  if (key->diffie_hellman)
    node = ssh_pk_add_nnode(tree, node, "dh", key->diffie_hellman->name,
                            &flag);
  ssh_ntree_generate_string(tree, &tmp);
  ssh_ntree_free(tree);

  return tmp;
}

/* Generate the full name of a particular public key. */
DLLEXPORT char * DLLCALLCONV
ssh_public_key_name(SshPublicKey key)
{
  SshNameTree tree;
  SshNameNode node;
  char *tmp;
  Boolean flag = FALSE;
  
  ssh_ntree_allocate(&tree);

  node = ssh_ntree_add_child(tree, NULL,
                             key->type->name);
  if (key->signature)
    node = ssh_pk_add_nnode(tree, node, "sign", key->signature->name, &flag);
  if (key->encryption)
    node = ssh_pk_add_nnode(tree, node, "encrypt", key->encryption->name,
                            &flag);
  if (key->diffie_hellman)
    node = ssh_pk_add_nnode(tree, node, "dh", key->diffie_hellman->name,
                            &flag);
  ssh_ntree_generate_string(tree, &tmp);
  ssh_ntree_free(tree);

  return tmp;
}

SshCryptoStatus ssh_private_key_set_scheme(SshPrivateKey key,
                                           void *scheme,
                                           SshPkSchemeFlag flag)
{
  /* Set the corresponding scheme. */
  switch (flag)
    {
    case SSH_PK_SCHEME_SIGN:
      key->signature = scheme;
      break;
    case SSH_PK_SCHEME_ENCRYPT:
      key->encryption = scheme;
      break;
    case SSH_PK_SCHEME_DH:
      key->diffie_hellman = scheme;
      break;
      /* XXX case SSH_PK_SCHEME_UDH:
      key->unified_diffie_hellman = scheme;
      break;*/
    case SSH_PK_SCHEME_OWA:
      key->one_way_auth = scheme;
      break;
    case SSH_PK_SCHEME_TWA:
      key->two_way_auth = scheme;
      break;
    case SSH_PK_SCHEME_MQV:
      key->mqv = scheme;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Set scheme to given void pointer. These routines should be used with
   caution because no checking is done to verify that given pointer is
   valid. */

SshCryptoStatus ssh_public_key_set_scheme(SshPublicKey key,
                                          void *scheme,
                                          SshPkSchemeFlag flag)
{
  /* Set the corresponding scheme. */
  switch (flag)
    {
    case SSH_PK_SCHEME_SIGN:
      key->signature = scheme;
      break;
    case SSH_PK_SCHEME_ENCRYPT:
      key->encryption = scheme;
      break;
    case SSH_PK_SCHEME_DH:
      key->diffie_hellman = scheme;
      break;
      /* XXX case SSH_PK_SCHEME_UDH:
      key->unified_diffie_hellman = scheme;
      break;*/
    case SSH_PK_SCHEME_OWA:
      key->one_way_auth = scheme;
      break;
    case SSH_PK_SCHEME_TWA:
      key->two_way_auth = scheme;
      break;
    case SSH_PK_SCHEME_MQV:
      key->mqv = scheme;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_pk_group_set_scheme(SshPkGroup group,
                                        void *scheme,
                                        SshPkSchemeFlag flag)
{
  switch (flag)
    {
    case SSH_PK_SCHEME_SIGN:
    case SSH_PK_SCHEME_ENCRYPT:
      /* XXX case SSH_PK_SCHEME_UDH: */
    case SSH_PK_SCHEME_OWA:
    case SSH_PK_SCHEME_TWA:
    case SSH_PK_SCHEME_MQV:
      /* Lets just ignore these, not considered errorneous. Main reason for
         this is the fact that some of these might want to add some
         information to the action_make context and we don't want to
         restrict that. */
      break;
    case SSH_PK_SCHEME_DH:
      group->diffie_hellman = scheme;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Generate the full name of a particular pk group. */
DLLEXPORT char * DLLCALLCONV
ssh_pk_group_name(SshPkGroup group)
{
  SshNameTree tree;
  SshNameNode node;
  char *tmp;
  
  ssh_ntree_allocate(&tree);

  node = ssh_ntree_add_child(tree, NULL,
                             group->type->name);
  if (group->diffie_hellman)
    {
      node = ssh_ntree_add_next(tree, node,
                                "dh");
      ssh_ntree_add_child(tree, node,
                          group->diffie_hellman->name);
    }
  ssh_ntree_generate_string(tree, &tmp);
  ssh_ntree_free(tree);

  return tmp;
}

SshCryptoStatus ssh_pk_group_get_scheme_name(SshPkGroup group,
                                             const char **name,
                                             SshPkSchemeFlag flag)
{
  switch (flag)
    {
    case SSH_PK_SCHEME_DH:
      *name = group->diffie_hellman->name;
      break;
    default:
      return SSH_CRYPTO_LIBRARY_CORRUPTED;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Function to retrieve a comma separated list of supported predefined
   groups for this particular key type. */

DLLEXPORT char * DLLCALLCONV
ssh_public_key_get_predefined_groups(const char *key_type)
{
  SshNameTree tree;
  SshNameNode node;
  SshNameTreeStatus nstat;
  const char *tmp;
  unsigned int i;
  
  /* Generate a name tree from key type. */
  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(key_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  tmp = ssh_nnode_get_identifier(node);

  /* Free the allocated tree now; we are not going to need it later. */
  ssh_ntree_free(tree);
  
  for (i = 0; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, tmp) == 0)
        {
          return (*ssh_key_types[i].pk_group_get_predefined_groups)();
        }
    }
  return NULL;
}

/* Parameter functions named here as ssh pk group (standing for
   ssh public key group). */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_generate(SshRandomState state,
                      SshPkGroup *group,
                      const char *group_type, ...)
{
  SshCryptoStatus status;
  unsigned int i;
  const SshPkAction *action;
  SshPkGroup pk_group;
  void *context;
  void *scheme;
  SshPkFormat format;
  SshNameTree tree;
  SshNameNode node, child;
  SshNameTreeStatus nstat;
  const char *name;
  char *tmp;
  va_list ap;

  /* Parse given group type. */
  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(group_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
    }
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
    }
  tmp = ssh_nnode_get_identifier(node);
  
  va_start(ap, group_type);
  
  for (i = 0; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, tmp) == 0)
        {
          /* Free allocated name. */
          ssh_xfree(tmp);
          node = ssh_nnode_get_child(node);
          
          /* Type matches i.e. we've found our key type, so continue with
             finding schemes and parameters. */

          /* Allocate private key context. */
          pk_group = ssh_xmalloc(sizeof(*pk_group));
          pk_group->type = &ssh_key_types[i];

          /* Clear pointers. */
          pk_group->diffie_hellman = NULL;

          /* Initialize actions, and verify that context was allocated. */
          context = (*pk_group->type->pk_group_action_init)(state);
          if (context == NULL)
            {
              ssh_xfree(pk_group);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }

          status = SSH_CRYPTO_OK;
          /* Run through all preselected schemes in the group_type. */
          while (node)
            {
              tmp = ssh_nnode_get_identifier(node);
              action = ssh_pk_find_scheme_action(pk_group->type->action_list,
                                                 tmp,
                                                 SSH_PK_FLAG_PK_GROUP);
              ssh_xfree(tmp);
              if (!action)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }
              child = ssh_nnode_get_child(node);
              if (child == NULL)
                /* We are not yet confident that there does not exists
                   a method of this name. Thus because for some schemes
                   it is easier to just write the scheme class, we
                   try to match for a fixed name. */
                tmp = SSH_PK_USUAL_NAME;
              else
                tmp = ssh_nnode_get_identifier(child);
              /* Find the scheme of that name. */
              scheme = ssh_pk_find_generic(tmp, action->type,
                                           action->type_size);
              if (child)
                /* Free if there is a need for that. */
                ssh_xfree(tmp);
              if (scheme == NULL)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }

              /* Call action_scheme if not set to NULL. */
              if (((SshPkGen *)scheme)->action_scheme != NULL)
                (*((SshPkGen *)scheme)->action_scheme)(context);
              
              /* Set the corresponding scheme to the group. */
              status = ssh_pk_group_set_scheme(pk_group, scheme,
                                               action->scheme_flag);

              if (status != SSH_CRYPTO_OK)
                break;

              /* Move to the next scheme. */
              node = ssh_nnode_get_next(node);
            }
          ssh_ntree_free(tree);
          if (status != SSH_CRYPTO_OK)
            {
              (*pk_group->type->pk_group_action_free)(context);
              ssh_xfree(pk_group);
              va_end(ap);
              return status;
            }

          /* Start reading the vararg list. */
          while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
            {
              /* Search name from command lists. */
              
              action = ssh_pk_find_action(format,
                                          pk_group->type->action_list,
                                          SSH_PK_FLAG_PK_GROUP);
              if (!action)
                {
                  /* Free the action context. */
                  (*pk_group->type->pk_group_action_free)(context);
                  ssh_xfree(pk_group);
                  va_end(ap);
                  return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
                }

              /* Supported only scheme selection and special operations. */
              switch (action->flags &
                      (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL))
                {
                case SSH_PK_FLAG_SCHEME:
                  name = va_arg(ap, const char *);
                  scheme = ssh_pk_find_generic(name, action->type,
                                               action->type_size);
                  if (scheme == NULL)
                    {
                      (*pk_group->type->pk_group_action_free)(context);
                      ssh_xfree(pk_group);
                      va_end(ap);
                      return SSH_CRYPTO_SCHEME_UNKNOWN;
                    }

                  /* Call action_scheme if not set to NULL. */
                  if (((SshPkGen *)scheme)->action_scheme != NULL)
                    (*((SshPkGen *)scheme)->action_scheme)(context);
                  
                  /* Set the corresponding scheme to the group. */
                  status = ssh_pk_group_set_scheme(pk_group, scheme,
                                                   action->scheme_flag);

                  if (status != SSH_CRYPTO_OK)
                    {
                      (*pk_group->type->pk_group_action_free)(context);
                      ssh_xfree(pk_group);
                      va_end(ap);
                      return status;
                    }
                  break;
                case SSH_PK_FLAG_SPECIAL:
                  /* Assume no wrappings. */
                  if (action->flags & SSH_PK_FLAG_WRAPPED)
                    {
                      if (action->action_put)
                        ssh_fatal("ssh_pk_group_generate: cannot wrap.");
                      va_end(ap);
                      (*pk_group->type->pk_group_action_free)(context);
                      ssh_xfree(pk_group);
                      return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
                    }
                  
                  if ((*action->action_put)(context, &ap, NULL, format) != 1)
                    {
                      (*pk_group->type->pk_group_action_free)(context);
                      ssh_xfree(pk_group);
                      va_end(ap);
                      return SSH_CRYPTO_LIBRARY_CORRUPTED;
                    }
                  break;
                default:
                  ssh_fatal("ssh_pk_group_generate: internal error.");
                  break;
                }      
            }

          /* Make the key and remove context. (One could incorporate making
             and freeing, however this way things seem to work also). */
          pk_group->context =
            (*pk_group->type->pk_group_action_make)(context);
          (*pk_group->type->pk_group_action_free)(context);

          /* Quit unhappily. */
          if (pk_group->context == NULL)
            {
              ssh_xfree(pk_group);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }
          
          /* Quit happily. */
          *group = pk_group;
          va_end(ap);
          
          return SSH_CRYPTO_OK;
        }
    }

  ssh_ntree_free(tree);
  va_end(ap);

  return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
}

DLLEXPORT void DLLCALLCONV
ssh_pk_group_free(SshPkGroup group)
{
  if (group == NULL || group->context == NULL)
    ssh_fatal("ssh_pk_group_free: undefined group.");
  (*group->type->pk_group_free)(group->context);
  group->context = NULL;
  ssh_xfree(group);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_select_scheme(SshPkGroup group, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  void *scheme;
  SshPkFormat format;
  const char *name;
  va_list ap;

  if (group->type == NULL)
    return SSH_CRYPTO_KEY_UNINITIALIZED;

  va_start(ap, group);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      action = ssh_pk_find_action(format, group->type->action_list,
                                  SSH_PK_FLAG_SCHEME |
                                  SSH_PK_FLAG_PK_GROUP);
      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      /* Find the new scheme. */
      name = va_arg(ap, const char *);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);
      /* Check that scheme exists. */
      if (scheme == NULL)
        {
          va_end(ap);
          return SSH_CRYPTO_SCHEME_UNKNOWN;
        }
        
      status = ssh_pk_group_set_scheme(group, scheme, action->scheme_flag);
      if (status != SSH_CRYPTO_OK)
        {
          va_end(ap);
          return status;
        }
    }
  va_end(ap);
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_get_info(SshPkGroup group, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char **name_ptr;
  va_list ap;
  
  va_start(ap, group);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      /* Seek for the action. */
      action = ssh_pk_find_action(format, group->type->action_list,
                                  SSH_PK_FLAG_PK_GROUP);

      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      switch (action->flags & (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL |
                               SSH_PK_FLAG_KEY_TYPE))
        {
        case SSH_PK_FLAG_KEY_TYPE:
          name_ptr = va_arg(ap, const char **);
          *name_ptr = group->type->name; /* XXX ssh_pk_group_name(group); */
          break;
        case SSH_PK_FLAG_SCHEME:
          name_ptr = va_arg(ap, const char **);
          
          status = ssh_pk_group_get_scheme_name(group,
                                                name_ptr,
                                                action->scheme_flag);
          if (status != SSH_CRYPTO_OK)
            {
              va_end(ap);
              return status;
            }
          break;
        case SSH_PK_FLAG_SPECIAL:
          if (action->flags & SSH_PK_FLAG_WRAPPED)
            {
              if (action->action_get)
                ssh_fatal("ssh_pk_group_get_info: cannot wrap.");
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
            }
          if ((*action->action_get)(group->context, &ap, NULL, format) != 1)
            {
              va_end(ap);
              return SSH_CRYPTO_LIBRARY_CORRUPTED;
            }
          break;
        default:
          ssh_fatal("ssh_private_key_get_info: internal error.");
          break;
        }
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_generate_randomizer(SshPkGroup group, SshRandomState state)
{
  (*group->type->pk_group_generate_randomizer)(group->context, state);
  return SSH_CRYPTO_OK;
}

DLLEXPORT unsigned int DLLCALLCONV
ssh_pk_group_count_randomizers(SshPkGroup group)
{
  return (*group->type->pk_group_count_randomizers)(group->context);
}

/* Returns atleast one randomizer if buffer is long enough, else some
   appropriate error message.

   Output buffer contains magic cookie which is computed either with
   a hash function or some other means. Other very suitable possibility
   is to add the parameter information into the buffer. 
   */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_export_randomizers(SshPkGroup group,
                                unsigned char **buf,
                                size_t *buf_length)
{
  SshBuffer buffer;
  unsigned char *tmp_buffer;
  size_t tmp_buf_len;
  
  ssh_buffer_init(&buffer);

  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32,
                    (SshUInt32) SSH_PK_GROUP_RANDOMIZER_MAGIC,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_END);

  while (1)
    {
      (*group->type->pk_group_export_randomizer)(group,
                                                 &tmp_buffer,
                                                 &tmp_buf_len);
      if (tmp_buffer == NULL)
        break;

      ssh_encode_buffer(&buffer,
                        SSH_FORMAT_UINT32_STR, tmp_buffer, tmp_buf_len, 
                        SSH_FORMAT_END);
    }

  *buf_length = ssh_buffer_len(&buffer);
  *buf = ssh_xmalloc(*buf_length);
  memcpy(*buf, ssh_buffer_ptr(&buffer), *buf_length);

  /* Set total length. */
  SSH_PUT_32BIT((*buf) + 4, *buf_length);

  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Add randomizers to randomizer list. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_import_randomizers(SshPkGroup group,
                                unsigned char *buf,
                                size_t buf_length)
{
  SshBuffer buffer;
  SshInt32 total_length, length;
  SshUInt32 magic;
  
  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, buf, buf_length);

  ssh_decode_buffer(&buffer,
                    SSH_FORMAT_UINT32, &magic,
                    SSH_FORMAT_UINT32, &total_length,
                    SSH_FORMAT_END);

  if (magic != SSH_PK_GROUP_RANDOMIZER_MAGIC)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  total_length -= 8;
  
  while (total_length > 0)
    {
      if (ssh_decode_buffer(&buffer,
                            SSH_FORMAT_UINT32, &length,
                            SSH_FORMAT_END) == 0)
        {
          ssh_buffer_uninit(&buffer);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      if ((*group->type->pk_group_import_randomizer)(group->context,
                                                     ssh_buffer_ptr(&buffer),
                                                     length) == FALSE)
        {
          ssh_buffer_uninit(&buffer);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      ssh_buffer_consume(&buffer, length);
      total_length -= (length + 4);
    }
  
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Pk group format:

   uint32   magic
   uint32   total length
   uint32   group type name length n
   n bytes  group type name (contains also information on schemes)

   uint32   type specific part length n
   n bytes  type specific part
   */
   
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_export(SshPkGroup group, unsigned char **buf,
                    size_t *buf_length)
{
  SshBuffer buffer;
  unsigned char *tmp_buf;
  size_t tmp_buf_len;
  char *name;
  
  ssh_buffer_init(&buffer);

  name = ssh_pk_group_name(group);
  
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) SSH_PK_GROUP_MAGIC,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_UINT32_STR, name, strlen(name),
                    SSH_FORMAT_END);

  ssh_xfree(name);
  
  if ((*group->type->pk_group_export)(group->context,
                                      &tmp_buf, &tmp_buf_len) == FALSE)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR, tmp_buf, tmp_buf_len,
                    SSH_FORMAT_END);

  ssh_xfree(tmp_buf);
  
  *buf_length = ssh_buffer_len(&buffer);
  *buf = ssh_xmalloc(*buf_length);
  memcpy(*buf, ssh_buffer_ptr(&buffer), *buf_length);

  /* Set total length. */
  SSH_PUT_32BIT((*buf) + 4, *buf_length);
  
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_import(unsigned char *buf, size_t buf_length,
                    SshPkGroup *group)
{
  SshBuffer buffer;
  SshUInt32 magic, total_length, length;
  size_t key_type_len;
  char *key_type, *name;
  const SshPkAction *action;
  void *scheme;
  SshPkGroup pk_group;
  SshNameTree tree;
  SshNameNode node;
  SshCryptoStatus status;
  unsigned int i;
  
  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, buf, buf_length);

  if (ssh_decode_buffer(&buffer,
                        SSH_FORMAT_UINT32, &magic,
                        SSH_FORMAT_UINT32, &total_length,
                        SSH_FORMAT_UINT32_STR,
                        &key_type, &key_type_len,
                        SSH_FORMAT_END) == 0)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  if (magic != SSH_PK_GROUP_MAGIC)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  ssh_ntree_allocate(&tree);
  ssh_ntree_parse(key_type, tree);
  node = ssh_ntree_get_root(tree);
  name = ssh_nnode_get_identifier(node);
  
  /* Find correct key type. We could use action lists now, but for
     simplicity don't. However with some other formats action lists and
     ssh_pk_group_generate might allow simpler implementation. */

  for (i = 0, pk_group = NULL; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, name) == 0)
        {
          /* Allocate */
          pk_group = ssh_xmalloc(sizeof(*pk_group));
          pk_group->type = &ssh_key_types[i];

          /* Initialize. */
          pk_group->diffie_hellman = NULL;

          break;
        }
    }
  ssh_xfree(name);
  node = ssh_nnode_get_child(node);
  
  if (pk_group == NULL)
    {
      ssh_ntree_free(tree);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }

  status = SSH_CRYPTO_OK;
  /* Check the name tree for schemes. */
  while (node)
    {
      name = ssh_nnode_get_identifier(node);
      action = ssh_pk_find_scheme_action(pk_group->type->action_list,
                                         name,
                                         SSH_PK_FLAG_PK_GROUP);
      ssh_xfree(name);
      if (!action)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      name = ssh_nnode_get_identifier(node);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);
      ssh_xfree(name);
      if (scheme == NULL)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      status = ssh_pk_group_set_scheme(pk_group, scheme,
                                       action->scheme_flag);
      if (status != SSH_CRYPTO_OK)
        {
          break;
        }
      node = ssh_nnode_get_parent(node);
      if (node)
        node = ssh_nnode_get_next(node);
    }
  
  ssh_ntree_free(tree);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_xfree(pk_group);
      ssh_buffer_uninit(&buffer);
      return status;
    }

  /* Read the final part and generate internal context. */
  if (ssh_decode_buffer(&buffer,
                        SSH_FORMAT_UINT32, &length,
                        SSH_FORMAT_END) == 0 ||
      length > ssh_buffer_len(&buffer))
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(pk_group);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  
  if ((*pk_group->type->pk_group_import)(ssh_buffer_ptr(&buffer),
                                         length,
                                         &pk_group->context) == FALSE)
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(pk_group);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  ssh_buffer_consume(&buffer, length);

  /* Set for output. */
  *group = pk_group;
  
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Private key functions. */

/* Private key generation and initialization. this interface allows several
   operations. Most noteworthy uses are:

     initialization of keys (with given values)
     generation of keys (with generated values)

   also

     selection of used schemes (although this can be done also with
       ssh_private_key_select_scheme(...) interface, which is probably
       more suitable).

   We use vararg lists, although not easy to debug they make this interface
   very flexible (atleast considering these few algorithm families).
       
   */
       
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_generate(SshRandomState state,
                         SshPrivateKey *key,
                         const char *key_type, ...)
{
  SshCryptoStatus status = SSH_CRYPTO_UNKNOWN_KEY_TYPE;
  SshPrivateKey private_key;
  SshPkGroup group;
  const SshPkAction *action;
  SshPkFormat format;
  SshNameTree tree;
  SshNameNode node, child;
  SshNameTreeStatus nstat;
  const char *name;
  void *wrapper;
  char *tmp;
  void *scheme;
  void *context;
  unsigned int i;
  va_list ap;

  /* Parse given group type. */
  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(key_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  tmp = ssh_nnode_get_identifier(node);

  /* Start reading va_arg list. */
  va_start(ap, key_type);
  
  for (i = 0; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, tmp) == 0)
        {
          ssh_xfree(tmp);
          node = ssh_nnode_get_child(node);
          
          /* Type matches i.e. we've found our key type, so continue with
             finding schemes and parameters. */

          /* Allocate private key context. */
          private_key = ssh_xmalloc(sizeof(*private_key));
          private_key->type = &ssh_key_types[i];

          /* Clear pointers. */
          private_key->signature = NULL;
          private_key->encryption = NULL;
          private_key->diffie_hellman = NULL;
          /* XXX private_key->unified_diffie_hellman = NULL; */
          private_key->one_way_auth = NULL;
          private_key->two_way_auth = NULL;
          private_key->mqv = NULL;

          
          /* Initialize actions, and verify that context was allocated. */
          context = (*private_key->type->private_key_action_init)(state);
          if (context == NULL)
            {
              ssh_xfree(private_key);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }

          status = SSH_CRYPTO_OK;
          /* Run through all preselected schemes in the group_type. */
          while (node)
            {
              tmp = ssh_nnode_get_identifier(node);
              action =
                ssh_pk_find_scheme_action(private_key->type->action_list,
                                          tmp,
                                          SSH_PK_FLAG_PRIVATE_KEY);
              ssh_xfree(tmp);
              if (!action)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }
              child = ssh_nnode_get_child(node);
              if (child == NULL)
                tmp = SSH_PK_USUAL_NAME;
              else
                tmp = ssh_nnode_get_identifier(child);
              scheme = ssh_pk_find_generic(tmp, action->type,
                                           action->type_size);
              if (child)
                ssh_xfree(tmp);
              if (scheme == NULL)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }

              /* Call action_scheme if not set to NULL. */
              if (((SshPkGen *)scheme)->action_scheme != NULL)
                (*((SshPkGen *)scheme)->action_scheme)(context);
              
              /* Set the corresponding scheme to the group. */
              status = ssh_private_key_set_scheme(private_key, scheme,
                                                  action->scheme_flag);

              if (status != SSH_CRYPTO_OK)
                {
                  break;
                }
              /* Move to the next scheme. */
              node = ssh_nnode_get_next(node);
            }
          ssh_ntree_free(tree);
          if (status != SSH_CRYPTO_OK)
            {
              (*private_key->type->private_key_action_free)(context);
              ssh_xfree(private_key);
              va_end(ap);
              return status;
            }

          /* Parse vararg list. */
          while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
            {
              /* Search name from command lists. */
              
              action = ssh_pk_find_action(format,
                                          private_key->type->action_list,
                                          SSH_PK_FLAG_PRIVATE_KEY);
              if (!action)
                {
                  (*private_key->type->private_key_action_free)(context);
                  ssh_xfree(private_key);
                  va_end(ap);
                  return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
                }

              /* Supported only scheme selection and special operations. */
              switch (action->flags &
                      (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL))
                {
                case SSH_PK_FLAG_SCHEME:
                  name = va_arg(ap, const char *);
                  scheme = ssh_pk_find_generic(name, action->type,
                                               action->type_size);
                  if (scheme == NULL)
                    {
                      (*private_key->type->private_key_action_free)(context);
                      ssh_xfree(private_key);
                      va_end(ap);
                      return SSH_CRYPTO_SCHEME_UNKNOWN;
                    }

                  /* Call the action_scheme function here if not
                     NULL. */
                  if (((SshPkGen *)scheme)->action_scheme != NULL)
                    (*((SshPkGen *)scheme)->action_scheme)(context);
                  
                  /* Set the corresponding scheme. */
                  status = ssh_private_key_set_scheme(private_key, scheme,
                                                      action->scheme_flag);
                  if (status != SSH_CRYPTO_OK)
                    {
                      (*private_key->type->private_key_action_free)(context);
                      ssh_xfree(private_key);
                      va_end(ap);
                      return status;
                    }
                  break;
                case SSH_PK_FLAG_SPECIAL:

                  /* Assume we don't use wrappings. */
                  wrapper = NULL;
                  if (action->flags & SSH_PK_FLAG_WRAPPED)
                    {
                      /* We assume that parameters are wrapped over
                         group structure. */
                      group = va_arg(ap, SshPkGroup);
                      wrapper = group->context;
                      /* For compatibility set also the Diffie-Hellman field.
                       */
                      private_key->diffie_hellman = group->diffie_hellman;
                    }
                  

                  if ((*action->action_put)(context, &ap, wrapper,
                                            format) != 1)
                    {
                      (*private_key->type->private_key_action_free)(context);
                      ssh_xfree(private_key);
                      va_end(ap);
                      return SSH_CRYPTO_LIBRARY_CORRUPTED;
                    }
                  break;
                default:
                  ssh_fatal("ssh_private_key_generate: internal error.");
                  break;
                }      
            }

          /* Make the key and remove context. (One could incorporate making
             and freeing, however this way things seem to work also). */
          private_key->context =
            (*private_key->type->private_key_action_make)(context);
          (*private_key->type->private_key_action_free)(context);

          /* Quit unhappily. */
          if (private_key->context == NULL)
            {
              ssh_xfree(private_key);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }
          
          /* Quit happily. */
          *key = private_key;
          va_end(ap);

          return SSH_CRYPTO_OK;
        }
    }

  ssh_ntree_free(tree);
  va_end(ap);

  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
}

/* Select new scheme to be used. That is assuming key supports many
   different schemes and/or padding types this can be of some use. Note
   however, that the key stays the same and some method assume keys to be
   of certain form. Such an example is DSA which by standard needs to have
   parameters of certain form, but this function could easily switch to
   DSA with key that is not of that form. Nevertheless I feel that such
   problems do not make switching to other methods unusable (even DSA
   would work with different parameters, although would not conform to
   the digital signature standard). */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_select_scheme(SshPrivateKey key, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  void *scheme;
  const char *name;
  va_list ap;

  if (key->type == NULL)
    return SSH_CRYPTO_KEY_UNINITIALIZED;

  va_start(ap, key);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      action = ssh_pk_find_action(format, key->type->action_list,
                                  SSH_PK_FLAG_SCHEME |
                                  SSH_PK_FLAG_PRIVATE_KEY);
      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      /* Find the new scheme. */
      name = va_arg(ap, const char *);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);

      /* Quit an awful error! Means that our scheme tables are either
         corrupted or application failed. */
      if (scheme == NULL)
        {
          va_end(ap);
          return SSH_CRYPTO_SCHEME_UNKNOWN;
        }
        
      status = ssh_private_key_set_scheme(key, scheme, action->scheme_flag);
      if (status != SSH_CRYPTO_OK)
        {
          va_end(ap);
          return status;
        }
    }
  va_end(ap);
  return SSH_CRYPTO_OK;
}

/* This function is needed in X.509 certificate routines. What is
   needed, is a way that creates from a bunch of stuff a valid SshPublicKey
   through sshcrypt header file.

   This will not be the final version, and in any case there should be no
   need for such things like random numbers anyway. We are not actually
   generating anything.
   */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_define(SshPublicKey *public_key, const char *key_type, ...)
{
  SshCryptoStatus status = SSH_CRYPTO_UNKNOWN_KEY_TYPE;
  SshPublicKey pub_key;
  SshPkGroup group;
  const SshPkAction *action;
  SshPkFormat format;
  SshNameTree tree;
  SshNameNode node, child;
  SshNameTreeStatus nstat;
  const char *name;
  void *wrapper;
  char *tmp;
  void *scheme;
  void *context;
  unsigned int i;
  va_list ap;

  /* Parse given group type. */
  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(key_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  tmp = ssh_nnode_get_identifier(node);

  /* Start reading va_arg list. */
  va_start(ap, key_type);

  /* Find out the key type. */
  for (i = 0; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, tmp) == 0)
        {
          ssh_xfree(tmp);
          node = ssh_nnode_get_child(node);
          
          /* Type matches i.e. we've found our key type, so continue with
             finding schemes and parameters. */

          /* Allocate private key context. */
          pub_key = ssh_xmalloc(sizeof(*pub_key));
          pub_key->type = &ssh_key_types[i];

          /* Clear pointers. */
          pub_key->signature = NULL;
          pub_key->encryption = NULL;
          pub_key->diffie_hellman = NULL;
          /* XXX pub_key->unified_diffie_hellman = NULL; */
          pub_key->one_way_auth = NULL;
          pub_key->two_way_auth = NULL;
          pub_key->mqv = NULL;

          /* Initialize actions, and verify that context was allocated. */
          context = (*pub_key->type->public_key_action_init)();
          if (context == NULL)
            {
              ssh_xfree(pub_key);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }

          status = SSH_CRYPTO_OK;
          /* Run through all preselected schemes in the group_type. */
          while (node)
            {
              tmp = ssh_nnode_get_identifier(node);
              action =
                ssh_pk_find_scheme_action(pub_key->type->action_list,
                                          tmp,
                                          SSH_PK_FLAG_PUBLIC_KEY);
              ssh_xfree(tmp);
              if (!action)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }
              child = ssh_nnode_get_child(node);
              if (child == NULL)
                tmp = SSH_PK_USUAL_NAME;
              else
                tmp = ssh_nnode_get_identifier(child);
              scheme = ssh_pk_find_generic(tmp, action->type,
                                           action->type_size);
              if (child)
                ssh_xfree(tmp);
              if (scheme == NULL)
                {
                  status = SSH_CRYPTO_SCHEME_UNKNOWN;
                  break;
                }

              /* Call action_scheme if not set to NULL. */
              if (((SshPkGen *)scheme)->action_scheme != NULL)
                (*((SshPkGen *)scheme)->action_scheme)(context);
              
              /* Set the corresponding scheme to the group. */
              status = ssh_public_key_set_scheme(pub_key, scheme,
                                                 action->scheme_flag);

              if (status != SSH_CRYPTO_OK)
                {
                  break;
                }
              /* Move to the next scheme. */
              node = ssh_nnode_get_next(node);
            }
          ssh_ntree_free(tree);
          if (status != SSH_CRYPTO_OK)
            {
              (*pub_key->type->public_key_action_free)(context);
              ssh_xfree(pub_key);
              va_end(ap);
              return status;
            }

          /* Parse vararg list. */
          while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
            {
              /* Search name from command lists. */
              
              action = ssh_pk_find_action(format,
                                          pub_key->type->action_list,
                                          SSH_PK_FLAG_PUBLIC_KEY);
              if (!action)
                {
                  (*pub_key->type->public_key_action_free)(context);
                  ssh_xfree(pub_key);
                  va_end(ap);
                  return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
                }

              /* Supported only scheme selection and special operations. */
              switch (action->flags &
                      (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL))
                {
                case SSH_PK_FLAG_SCHEME:
                  name = va_arg(ap, const char *);
                  scheme = ssh_pk_find_generic(name, action->type,
                                               action->type_size);
                  if (scheme == NULL)
                    {
                      (*pub_key->type->public_key_action_free)(context);
                      ssh_xfree(pub_key);
                      va_end(ap);
                      return SSH_CRYPTO_SCHEME_UNKNOWN;
                    }

                  /* Call the action_scheme function here if not
                     NULL. */
                  if (((SshPkGen *)scheme)->action_scheme != NULL)
                    (*((SshPkGen *)scheme)->action_scheme)(context);
                  
                  /* Set the corresponding scheme. */
                  status = ssh_public_key_set_scheme(pub_key, scheme,
                                                     action->scheme_flag);
                  if (status != SSH_CRYPTO_OK)
                    {
                      (*pub_key->type->public_key_action_free)(context);
                      ssh_xfree(pub_key);
                      va_end(ap);
                      return status;
                    }
                  break;
                case SSH_PK_FLAG_SPECIAL:

                  /* Assume we don't use wrappings. */
                  wrapper = NULL;
                  if (action->flags & SSH_PK_FLAG_WRAPPED)
                    {
                      /* We assume that parameters are wrapped over
                         group structure. */
                      group = va_arg(ap, SshPkGroup);
                      wrapper = group->context;
                      /* For compatibility set also the Diffie-Hellman field.
                       */
                      pub_key->diffie_hellman = group->diffie_hellman;
                    }

                  if ((*action->action_put)(context, &ap, wrapper,
                                            format) != 1)
                    {
                      (*pub_key->type->public_key_action_free)(context);
                      ssh_xfree(pub_key);
                      va_end(ap);
                      return SSH_CRYPTO_LIBRARY_CORRUPTED;
                    }
                  break;
                default:
                  ssh_fatal("ssh_public_key_define: internal error.");
                  break;
                }      
            }

          /* Make the key and remove context. (One could incorporate making
             and freeing, however this way things seem to work also). */
          pub_key->context =
            (*pub_key->type->public_key_action_make)(context);
          (*pub_key->type->public_key_action_free)(context);

          /* Quit unhappily. */
          if (pub_key->context == NULL)
            {
              ssh_xfree(pub_key);
              va_end(ap);
              return SSH_CRYPTO_OPERATION_FAILED;
            }
          
          /* Quit happily. */
          *public_key = pub_key;
          va_end(ap);

          return SSH_CRYPTO_OK;
        }
    }

  ssh_ntree_free(tree);
  va_end(ap);

  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
}

/* This is a little bit stupid, maybe same context for private and public
   key (internally) would be a good idea. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_select_scheme(SshPublicKey key, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char *name;
  void *scheme;
  va_list ap;

  if (key->type == NULL)
    return SSH_CRYPTO_KEY_UNINITIALIZED;

  va_start(ap, key);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      action = ssh_pk_find_action(format, key->type->action_list,
                                  SSH_PK_FLAG_SCHEME |
                                  SSH_PK_FLAG_PUBLIC_KEY);

      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      /* Find the new scheme. */
      name = va_arg(ap, const char *);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);

      /* Quit an awful error! Means that our scheme tables are either
         corrupted or application failed. */
      if (scheme == NULL)
        {
          va_end(ap);
          return SSH_CRYPTO_SCHEME_UNKNOWN;
        }
        
      status = ssh_public_key_set_scheme(key, scheme, action->scheme_flag);
      if (status != SSH_CRYPTO_OK)
        {
          va_end(ap);
          return status;
        }
    }
  va_end(ap);
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_get_info(SshPrivateKey key, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char **name_ptr;
  va_list ap;
  
  va_start(ap, key);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      /* Seek for the action. */
      action = ssh_pk_find_action(format, key->type->action_list,
                                  SSH_PK_FLAG_PRIVATE_KEY);

      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      switch (action->flags & (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL |
                               SSH_PK_FLAG_KEY_TYPE))
        {
        case SSH_PK_FLAG_KEY_TYPE:
          name_ptr = va_arg(ap, const char **);
          *name_ptr = key->type->name; /* ssh_private_key_name(key); */
          break;
        case SSH_PK_FLAG_SCHEME:
          name_ptr = va_arg(ap, const char **);
          
          status = ssh_private_key_get_scheme_name(key,
                                                   name_ptr,
                                                   action->scheme_flag);
          if (status != SSH_CRYPTO_OK)
            {
              va_end(ap);
              return status;
            }

          break;
        case SSH_PK_FLAG_SPECIAL:
          if (action->flags & SSH_PK_FLAG_WRAPPED)
            {
              if (action->action_get)
                ssh_fatal("ssh_private_key_get_info: cannot wrap.");
              return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
            }

          if ((*action->action_get)(key->context, &ap, NULL, format) != 1)
            return SSH_CRYPTO_LIBRARY_CORRUPTED;
          break;
        default:
          ssh_fatal("ssh_private_key_get_info: internal error.");
          break;
        }
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_get_info(SshPublicKey key, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char **name_ptr;
  va_list ap;
  
  va_start(ap, key);
  
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      /* Seek for the action. */
      action = ssh_pk_find_action(format, key->type->action_list,
                                  SSH_PK_FLAG_PUBLIC_KEY);

      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      switch (action->flags & (SSH_PK_FLAG_SCHEME | SSH_PK_FLAG_SPECIAL |
                               SSH_PK_FLAG_KEY_TYPE))
        {
        case SSH_PK_FLAG_KEY_TYPE:
          name_ptr = va_arg(ap, const char **);
          *name_ptr = key->type->name; /* ssh_public_key_name(key); */
          break;
        case SSH_PK_FLAG_SCHEME:
          name_ptr = va_arg(ap, const char **);
          
          status = ssh_public_key_get_scheme_name(key,
                                                  name_ptr,
                                                  action->scheme_flag);
          if (status != SSH_CRYPTO_OK)
            {
              va_end(ap);
              return status;
            }

          break;
        case SSH_PK_FLAG_SPECIAL:
          if (action->flags & SSH_PK_FLAG_WRAPPED)
            {
              if (action->action_get)
                ssh_fatal("ssh_public_key_get_info: cannot wrap.");
              return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
            }
          
          if ((*action->action_get)(key->context, &ap, NULL, format) != 1)
            return SSH_CRYPTO_LIBRARY_CORRUPTED;
          break;
        default:
          ssh_fatal("ssh_public_key_get_info: internal error.");
          break;
        }
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

#if 0
DLLEXPORT Boolean DLLCALLCONV
ssh_public_key_type_supported_capability(const char *key_type,
                                         SshPkFormat test)
{
  return FALSE;
}
#endif

/* Names could be given by gathering all possible combinations, however,
   it might be more useful for outsider to get names for some specific
   class of algorithms. Such as signature, encryption or some key exchange
   method. */
DLLEXPORT char * DLLCALLCONV
ssh_public_key_get_supported(void)
{
  char *list;
  unsigned int i, j, k, l;
  const SshPkAction *action;
  const void *scheme_list;
  const char *scheme_list_name;
  SshNameTree tree;
  SshNameNode node;

  /* Allocate tree. */
  ssh_ntree_allocate(&tree);
  node = NULL;
  
  for (i = 0; ssh_key_types[i].name; i++)
    {
      /* Add key type node. */
      node = ssh_ntree_add_next(tree, node,
                                ssh_key_types[i].name);

      for (action = ssh_key_types[i].action_list, j = 0, l = 0;
           action[j].format != SSH_PKF_END; j++)
        {
          if ((action[j].flags & SSH_PK_FLAG_SCHEME) == SSH_PK_FLAG_SCHEME)
            {
              /* Add scheme identifier nodes. */
              if (l == 0)
                node = ssh_ntree_add_child(tree, node,
                                           action[j].scheme_class);
              else
                  node = ssh_ntree_add_next(tree, node,
                                            action[j].scheme_class);
              l++;
              for (scheme_list = action[j].type, k = 0;
                   (scheme_list_name =
                    ssh_pk_next_generic(&scheme_list,
                                        action[j].type_size)) != NULL; k++)
                {
                  /* Add actual algorithm identifiers.

                     XXX Note, here we don't wonder about the *_USUAL_NAME
                     thing. It is more straight forward to just forget
                     it here. Although, it would make things easier to
                     read. */
                  if (k == 0)
                    node = ssh_ntree_add_child(tree, node,
                                               scheme_list_name);
                  else
                    node = ssh_ntree_add_next(tree, node,
                                              scheme_list_name);
                }
              /* Go up if one went down. */
              if (k)
                node = ssh_nnode_get_parent(node);
            }
        }
      /* Go up if one went down. */
      if (l)
        node = ssh_nnode_get_parent(node);
    }

  ssh_ntree_generate_string(tree, &list);
  ssh_ntree_free(tree);
  
  return list;
}

/* Key format might look like:

   32bit    magic
   32bit    total length
   32bit    key type name length n
   n bytes  key type name (no zero terminator) (with schemes)
   
   32bit    algorithm specific part length n
   n bytes  algorithm specific part

   One should note, that the following key will be identical to the one
   inputed. Also it would be possible, by extending nametree system, to
   actually output the public key in ascii.
   
   */
   
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_import(const unsigned char *buf,
                      size_t len,
                      SshPublicKey *key)
{
  SshBuffer buffer;
  SshUInt32 pk_magic, pk_length, length;
  char *key_type;
  char *name;
  const SshPkAction *action;
  void *scheme;
  SshPublicKey public_key;
  unsigned int i;
  SshCryptoStatus status;
  SshNameTree tree;
  SshNameNode node, child;
  SshNameTreeStatus nstat; 
  
  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, buf, len);

  if (ssh_decode_buffer(&buffer,
                        SSH_FORMAT_UINT32, &pk_magic,
                        SSH_FORMAT_UINT32, &pk_length,
                        SSH_FORMAT_UINT32_STR, &key_type, NULL,
                        SSH_FORMAT_END) == 0)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }

  if (pk_magic != SSH_PUBLIC_KEY_MAGIC || pk_length < 8)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }

  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(key_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
      
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  name = ssh_nnode_get_identifier(node);
  
  /* Find correct key type. Done here, because we don't want to overuse
     vararg lists. */

  for (i = 0, public_key = NULL; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, name) == 0)
        {
          /* Initialize public key. */
          public_key = ssh_xmalloc(sizeof(*public_key));
          public_key->type = &ssh_key_types[i];

          public_key->signature = NULL;
          public_key->encryption = NULL;
          public_key->diffie_hellman = NULL;
          /* XXX public_key->unified_diffie_hellman = NULL; */
          public_key->one_way_auth = NULL;
          public_key->two_way_auth = NULL;
          public_key->mqv = NULL;
          
          break;
        }
    }
  ssh_xfree(name);
  node = ssh_nnode_get_child(node);
  if (public_key == NULL)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  status = SSH_CRYPTO_OK;
  /* Run through all preselected schemes in the group_type. */
  while (node)
    {
      name = ssh_nnode_get_identifier(node);
      action =
        ssh_pk_find_scheme_action(public_key->type->action_list,
                                  name,
                                  SSH_PK_FLAG_PUBLIC_KEY);
      ssh_xfree(name);
      if (!action)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      child = ssh_nnode_get_child(node);
      if (child == NULL)
        name = SSH_PK_USUAL_NAME;
      else
        name = ssh_nnode_get_identifier(child);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);
      if (child)
        ssh_xfree(name);
      if (scheme == NULL)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      /* Set the corresponding scheme to the group. */
      status = ssh_public_key_set_scheme(public_key, scheme,
                                         action->scheme_flag);
      
      if (status != SSH_CRYPTO_OK)
        {
          break;
        }
      /* Move to the next scheme. */
      node = ssh_nnode_get_next(node);
    }
  ssh_ntree_free(tree);
  ssh_xfree(key_type);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(public_key);
      return status;
    }

  if (ssh_decode_buffer(&buffer,
                        SSH_FORMAT_UINT32, &length,
                        SSH_FORMAT_END) == 0 ||
      length > ssh_buffer_len(&buffer))
    {
      ssh_xfree(public_key);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  
  /* Algorithm specific part. */
  if ((*public_key->type->public_key_import)(ssh_buffer_ptr(&buffer),
                                             length,
                                             &(public_key->context)) == FALSE)
    {
      ssh_buffer_uninit(&buffer);
      *key = NULL;
      ssh_xfree(public_key);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Advance */
  
  ssh_buffer_consume(&buffer, length);

  *key = public_key;
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_export(SshPublicKey key,
                      unsigned char **buf,
                      size_t *length_return)
{
  SshBuffer buffer;
  unsigned char *temp_buf;
  size_t temp_buf_len;
  char *name;
  
  ssh_buffer_init(&buffer);
  
  /* Encoding of the public key, in SSH format. */

  name = ssh_public_key_name(key);
  
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) SSH_PUBLIC_KEY_MAGIC,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_UINT32_STR, name, strlen(name),
                    SSH_FORMAT_END);
  ssh_xfree(name);
  
  if ((*key->type->public_key_export)(key->context,
                                      &temp_buf, &temp_buf_len) == FALSE)
    {
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR, temp_buf, temp_buf_len,
                    SSH_FORMAT_END);

  ssh_xfree(temp_buf);

  /* Get the buffer information. */
  *length_return = ssh_buffer_len(&buffer);
  *buf = ssh_xmalloc(*length_return);
  memcpy(*buf, ssh_buffer_ptr(&buffer), *length_return);

  /* Set total length. */
  SSH_PUT_32BIT(*buf + 4, *length_return);

  /* Free buffer. */
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_export_canonical(SshPublicKey key,
                                unsigned char **buf,
                                size_t *length_return)
{
  SshBuffer buffer;
  unsigned char *temp_buf;
  size_t temp_buf_len;
  
  /* Encoding of the public key, in SSH format. */

  if (key == NULL)
    return SSH_CRYPTO_OPERATION_FAILED;
  if (key->type == NULL)
    return SSH_CRYPTO_OPERATION_FAILED;

  if ((*key->type->public_key_export)(key->context,
                                      &temp_buf, &temp_buf_len) == FALSE)
    return SSH_CRYPTO_OPERATION_FAILED;
  
  ssh_buffer_init(&buffer);

  /* Build the blob. */
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) SSH_PUBLIC_KEY_MAGIC,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_UINT32_STR, key->type->name,
                    strlen(key->type->name),
                    SSH_FORMAT_UINT32_STR, temp_buf, temp_buf_len,
                    SSH_FORMAT_END);
  
  ssh_xfree(temp_buf);

  /* Get the buffer information. */
  *length_return = ssh_buffer_len(&buffer);
  *buf = ssh_xmalloc(*length_return);
  memcpy(*buf, ssh_buffer_ptr(&buffer), *length_return);

  /* Set total length. */
  SSH_PUT_32BIT(*buf + 4, *length_return);

  /* Free buffer. */
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Doing copy of the key_src, so that both keys can be altered without
   affecting the other. Note, that although keys might seem to be totally
   separate some features might be implemeted with reference counting. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_copy(SshPublicKey key_src,
                    SshPublicKey *key_dest)
{
  SshPublicKey created = ssh_xmalloc(sizeof(*created));

  /* First copy all basic internal stuff and then the context explicitly. */
  memcpy(created, key_src, sizeof(*created));
  (*key_src->type->public_key_copy)(key_src->context, &created->context);

  *key_dest = created;
  return SSH_CRYPTO_OK;
}

DLLEXPORT void DLLCALLCONV
ssh_public_key_free(SshPublicKey key)
{
  if (key == NULL || key->context == NULL)
    ssh_fatal("ssh_public_key_free: undefined key.");
  (key->type->public_key_free)(key->context);
  key->context = NULL;
  ssh_xfree(key);
}

/* Derive public key group for public key. */
DLLEXPORT SshPkGroup DLLCALLCONV
ssh_public_key_derive_pk_group(SshPublicKey key)
{
  SshPkGroup group;

  if (key->type->public_key_derive_pk_group == NULL)
    return NULL;

  group = ssh_xmalloc(sizeof(*group));
  group->type = key->type;
  (*key->type->public_key_derive_pk_group)(key->context,
                                           &group->context);
  /* Set up schemes for compatibility. */
  group->diffie_hellman = key->diffie_hellman;
  return group;
}

/* Report the maximal length of bytes which may be encrypted with this
   public key. Return 0 if encryption not available for this public key. */

DLLEXPORT size_t DLLCALLCONV
ssh_public_key_max_encrypt_input_len(SshPublicKey key)
{
  if (key->encryption == NULL)
    return 0;

  return (*key->encryption->public_key_max_encrypt_input_len)(key->context);
}

/* This is similar to the previous one, but the maximal output length
   is returned instead the of the maximum input length. */

DLLEXPORT size_t DLLCALLCONV
ssh_public_key_max_encrypt_output_len(SshPublicKey key)
{
  if (key->encryption == NULL)
    return 0;
  
  return (*key->encryption->public_key_max_encrypt_output_len)(key->context);
}

/* Import private key. */

SshCryptoStatus
ssh_private_key_import_internal(const unsigned char *buf,
                                size_t len,
                                const unsigned char *cipher_key,
                                size_t cipher_keylen,
                                SshPrivateKey *key,
                                Boolean expand_key)
{
  SshBuffer buffer;
  SshUInt32 pk_magic, pk_length, length, tmp_length;
  char *key_type, *cipher_name, *name;
  unsigned char *tmp_buf;
  size_t tmp_buf_length;
  unsigned int i;
  SshPrivateKey private_key;
  SshCipher cipher;
  SshCryptoStatus status;
  const SshPkAction *action;
  void *scheme;
  SshNameTree tree;
  SshNameNode node, child;
  SshNameTreeStatus nstat;
  
  ssh_buffer_init(&buffer);
  ssh_buffer_append(&buffer, buf, len);
  
  ssh_decode_buffer(&buffer,
                    SSH_FORMAT_UINT32, &pk_magic,
                    SSH_FORMAT_UINT32, &pk_length,
                    SSH_FORMAT_UINT32_STR, &key_type, NULL, 
                    SSH_FORMAT_END);

  if (pk_magic != SSH_PRIVATE_KEY_MAGIC || pk_length < 8)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  ssh_ntree_allocate(&tree);
  nstat = ssh_ntree_parse(key_type, tree);
  if (nstat != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }
  name = ssh_nnode_get_identifier(node);
  
  /* Find correct key type. */

  for (i = 0, private_key = NULL; ssh_key_types[i].name; i++)
    {
      if (strcmp(ssh_key_types[i].name, name) == 0)
        {
          /* Initialize public key. */
          private_key = ssh_xmalloc(sizeof(*private_key));
          private_key->type = &ssh_key_types[i];

          private_key->signature = NULL;
          private_key->encryption = NULL;
          private_key->diffie_hellman = NULL;
          /* XXX private_key->unified_diffie_hellman = NULL; */
          private_key->one_way_auth = NULL;
          private_key->two_way_auth = NULL;
          private_key->mqv = NULL;

          
          break;
        }
    }

  ssh_xfree(name);
  node = ssh_nnode_get_child(node);
  if (private_key == NULL)
    {
      ssh_ntree_free(tree);
      ssh_xfree(key_type);
      ssh_buffer_uninit(&buffer);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  status = SSH_CRYPTO_OK;
  /* Run through all preselected schemes in the group_type. */
  while (node)
    {
      name = ssh_nnode_get_identifier(node);
      action =
        ssh_pk_find_scheme_action(private_key->type->action_list,
                                  name,
                                  SSH_PK_FLAG_PRIVATE_KEY);
      ssh_xfree(name);
      if (!action)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      child = ssh_nnode_get_child(node);
      if (child == NULL)
        name = SSH_PK_USUAL_NAME;
      else
        name = ssh_nnode_get_identifier(child);
      scheme = ssh_pk_find_generic(name, action->type,
                                   action->type_size);
      if (child)
        ssh_xfree(name);
      if (scheme == NULL)
        {
          status = SSH_CRYPTO_SCHEME_UNKNOWN;
          break;
        }
      /* Set the corresponding scheme to the group. */
      status = ssh_private_key_set_scheme(private_key, scheme,
                                          action->scheme_flag);
      
      if (status != SSH_CRYPTO_OK)
        break;
      /* Move to the next scheme. */
      node = ssh_nnode_get_next(node);
    }
  ssh_ntree_free(tree);
  ssh_xfree(key_type);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(private_key);
      return status;
    }
  
  ssh_decode_buffer(&buffer,
                    SSH_FORMAT_UINT32_STR, &cipher_name, NULL, 
                    SSH_FORMAT_UINT32, &length,
                    SSH_FORMAT_END);

  tmp_buf_length = ssh_cipher_get_key_length(cipher_name);
  tmp_buf        = NULL;
  if (tmp_buf_length == 0)
    tmp_buf_length = 32;
  
  /* Check key len and expansion flag. */
  if (tmp_buf_length > cipher_keylen || expand_key)
    {
      /* Expand encryption key. */
      tmp_buf = ssh_xmalloc(tmp_buf_length);
      ssh_hash_expand_key_internal(tmp_buf, tmp_buf_length,
                                   cipher_key, cipher_keylen,
                                   NULL, 0,
                                   &ssh_hash_md5_def);
      
      cipher_key = tmp_buf;
      cipher_keylen = tmp_buf_length;
    }

  /* Allocate cipher. */
  if ((status = ssh_cipher_allocate(cipher_name, cipher_key,
                                    cipher_keylen,
                                    FALSE, &cipher)) != SSH_CRYPTO_OK)
    {
      ssh_xfree(cipher_name);
      ssh_buffer_uninit(&buffer);
      ssh_xfree(tmp_buf);
      ssh_xfree(private_key);
      return status;
    }
  ssh_xfree(tmp_buf);
  ssh_xfree(cipher_name);
  
  if (ssh_cipher_transform(cipher,
                           ssh_buffer_ptr(&buffer), ssh_buffer_ptr(&buffer),
                           length) != SSH_CRYPTO_OK)
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(private_key);
      ssh_cipher_free(cipher);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Free cipher immediately. */
  ssh_cipher_free(cipher);

  /* Algorithm specific part. */
  if (ssh_decode_buffer(&buffer,
                        SSH_FORMAT_UINT32, &tmp_length,
                        SSH_FORMAT_END) == 0 ||
      tmp_length > ssh_buffer_len(&buffer))
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(private_key);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  
  if ((*private_key->type->private_key_import)
      (ssh_buffer_ptr(&buffer),
       tmp_length,
       &(private_key->context)) == FALSE)
    {
      ssh_buffer_uninit(&buffer);
      ssh_xfree(private_key);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Advance (over padding etc.) */
  ssh_buffer_consume(&buffer, tmp_length);
  
  *key = private_key;
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Export a private key. */

SshCryptoStatus
ssh_private_key_export_internal(SshPrivateKey key,
                                const char *cipher_name,
                                const unsigned char *cipher_key,
                                size_t cipher_keylen,                  
                                SshRandomState state,
                                unsigned char **bufptr,
                                size_t *length_return,
                                Boolean expand_key)
{
  SshCryptoStatus status;
  SshBuffer buffer, encrypted;
  unsigned char byte;
  unsigned char *buf;
  size_t buf_length;
  SshCipher cipher;
  char *name;
  
  /* Check key len and expansion flag. */
  buf_length = ssh_cipher_get_key_length(cipher_name);
  buf        = NULL;
  if (buf_length == 0)
    buf_length = 32;
  
  if (buf_length > cipher_keylen || expand_key)
    {
      /* Expand encryption key. */
      buf = ssh_xmalloc(buf_length);
      ssh_hash_expand_key_internal(buf, buf_length,
                                   cipher_key, cipher_keylen,
                                   NULL, 0,
                                   &ssh_hash_md5_def);

      cipher_key    = buf;
      cipher_keylen = buf_length;
    }

  /* Allocate cipher. */
  if ((status = ssh_cipher_allocate(cipher_name,
                                    cipher_key, cipher_keylen,
                                    TRUE, 
                                    &cipher)) != SSH_CRYPTO_OK)
    {
      ssh_xfree(buf);
      return status;
    }
  /* Free the key buffer if it exists. */
  ssh_xfree(buf);

  /* Generate private key blob. */

  if ((*key->type->private_key_export)(key->context,
                                       &buf, &buf_length) == FALSE)
    {
      ssh_cipher_free(cipher);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Use buffer to append data. */
  ssh_buffer_init(&encrypted);

  ssh_encode_buffer(&encrypted,
                    SSH_FORMAT_UINT32_STR, buf, buf_length,
                    SSH_FORMAT_END);
  
  /* Free exact private key information. */
  memset(buf, 0, buf_length);
  ssh_xfree(buf);
  
  /* Add some padding. */
  while ((ssh_buffer_len(&encrypted) % ssh_cipher_get_block_length(cipher)) !=
         0)
    {
      byte = ssh_random_get_byte(state);
      ssh_buffer_append(&encrypted, &byte, 1);
    }
  
  /* Encrypt buffer. */
  if (ssh_cipher_transform(cipher, ssh_buffer_ptr(&encrypted),
                           ssh_buffer_ptr(&encrypted),
                           ssh_buffer_len(&encrypted)) != SSH_CRYPTO_OK)
    {
      ssh_buffer_uninit(&encrypted);
      ssh_cipher_free(cipher);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Free cipher. */
  ssh_cipher_free(cipher);

  /* Initialize the actual private key buffer. */
  ssh_buffer_init(&buffer);

  name = ssh_private_key_name(key);
  
  ssh_encode_buffer(&buffer,
                    SSH_FORMAT_UINT32, (SshUInt32) SSH_PRIVATE_KEY_MAGIC,
                    SSH_FORMAT_UINT32, (SshUInt32) 0,
                    SSH_FORMAT_UINT32_STR,
                    name, strlen(name),
                    SSH_FORMAT_UINT32_STR,
                    cipher_name, strlen(cipher_name),
                    SSH_FORMAT_UINT32_STR, 
                    ssh_buffer_ptr(&encrypted), ssh_buffer_len(&encrypted),
                    SSH_FORMAT_END);

  ssh_xfree(name);
  /* Free encrypted buffer. */
  ssh_buffer_uninit(&encrypted);

  /* Get the buffer information. */
  *length_return = ssh_buffer_len(&buffer);
  *bufptr = ssh_xmalloc(*length_return);
  memcpy(*bufptr, ssh_buffer_ptr(&buffer), *length_return);

  /* Set total length. */
  SSH_PUT_32BIT(*bufptr + 4, *length_return);

  /* Free buffer. */
  ssh_buffer_uninit(&buffer);

  return SSH_CRYPTO_OK;
}

/* Functions that are used from outside. These tell whether one wants to
   expand the key here or not. */
                           
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_import(const unsigned char *buf,
                       size_t len,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,
                       SshPrivateKey *key)
{
  return ssh_private_key_import_internal(buf, len,
                                         cipher_key, cipher_keylen,
                                         key, FALSE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_export(SshPrivateKey key,
                       const char *cipher_name,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,                   
                       SshRandomState state,
                       unsigned char **bufptr,
                       size_t *length_return)
{
  return ssh_private_key_export_internal(key, cipher_name,
                                         cipher_key, cipher_keylen,
                                         state,
                                         bufptr, length_return, FALSE);
}


DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_import_with_passphrase(const unsigned char *buf,
                                       size_t len,
                                       const char *passphrase,
                                       SshPrivateKey *key)
{
  return ssh_private_key_import_internal(buf, len,
                                         (unsigned char *) passphrase,
                                         strlen(passphrase),
                                         key, TRUE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_export_with_passphrase(SshPrivateKey key,
                                       const char *cipher_name,
                                       const char *passphrase,
                                       SshRandomState state,
                                       unsigned char **bufptr,
                                       size_t *length_return)
{
  if (strcmp(passphrase, "") == 0)
    cipher_name = "none";
  return ssh_private_key_export_internal(key, cipher_name,
                                         (unsigned char *) passphrase,
                                         strlen(passphrase),
                                         state,
                                         bufptr, length_return, TRUE);
}

/* Copy private keys */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_copy(SshPrivateKey key_src,
                     SshPrivateKey *key_dest)
{
  SshPrivateKey created = ssh_xmalloc(sizeof(*created));

  memcpy(created, key_src, sizeof(*created));
  (*key_src->type->private_key_copy)(key_src->context, &created->context);


  *key_dest = created;
  return SSH_CRYPTO_OK;
}
        
/* Release a private key structure. */

DLLEXPORT void DLLCALLCONV
ssh_private_key_free(SshPrivateKey key)
{
  if (key == NULL || key->context == NULL)
    ssh_fatal("ssh_private_key_free: undefined key.");


  (*key->type->private_key_free)(key->context);
  key->context = NULL;
  ssh_xfree(key);
}

DLLEXPORT SshPublicKey DLLCALLCONV
ssh_private_key_derive_public_key(SshPrivateKey key)
{
  SshPublicKey pub = ssh_xmalloc(sizeof(*pub));




  pub->type = key->type;
  (*key->type->private_key_derive_public_key)(key->context,
                                              &pub->context);

  /* Set up all schemes for compatibility. */
  pub->signature = key->signature;
  pub->encryption = key->encryption;
  pub->diffie_hellman = key->diffie_hellman;
  /* XXX pub->unified_diffie_hellman = key->unified_diffie_hellman; */
  pub->one_way_auth = key->one_way_auth;
  pub->two_way_auth = key->two_way_auth;
  pub->mqv = key->mqv;
  
  return pub;
}

DLLEXPORT SshPkGroup DLLCALLCONV
ssh_private_key_derive_pk_group(SshPrivateKey key)
{
  SshPkGroup group;

  if (key->type->private_key_derive_pk_group == NULL)
    return NULL;
  
  group = ssh_xmalloc(sizeof(*group));

  group->type = key->type;
  (*key->type->private_key_derive_pk_group)(key->context,
                                            &group->context);
  /* Set up schemes for compatibility. */
  group->diffie_hellman = key->diffie_hellman;
  return group;
}

/* XXX Signature hash function derivation functions. */

DLLEXPORT SshHash DLLCALLCONV
ssh_public_key_derive_signature_hash(SshPublicKey key)
{
  if (key->signature == NULL)
    return NULL;
  return ssh_hash_allocate_internal(key->signature->hash_def);
}

DLLEXPORT SshHash DLLCALLCONV
ssh_private_key_derive_signature_hash(SshPrivateKey key)
{
  if (key->signature == NULL)
    return NULL;
  return ssh_hash_allocate_internal(key->signature->hash_def);
}

/* Perform the public key encryption operation. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_encrypt(SshPublicKey key, 
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char *ciphertext_buffer,
                       size_t ssh_buffer_len,
                       size_t *ciphertext_len_return,
                       SshRandomState random_state)
{
  if (key->encryption == NULL)
    return SSH_CRYPTO_UNSUPPORTED;
  
  /* If true then encryption succeeded. */
  if ((*key->encryption->public_key_encrypt)(key->context,
                                             plaintext,
                                             plaintext_len,
                                             ciphertext_buffer,
                                             ssh_buffer_len,
                                             ciphertext_len_return,
                                             random_state,
                                             key->encryption->hash_def))
    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}

/* Verify a signature. In fact, decrypt the given signature with the
   public key, and then compare the decrypted data to the given
   (supposedly original) data. If the decrypted data and the given
   data are identical (in the sense that they are of equal length and
   their contents are bit-wise same) the function returns TRUE,
   otherways FALSE. */

DLLEXPORT Boolean DLLCALLCONV
ssh_public_key_verify_signature(SshPublicKey key,
                                const unsigned char *signature,
                                size_t signature_len,
                                const unsigned char *data,
                                size_t data_len)
{
  if (key->signature == NULL)
    return FALSE;
  
  return (*key->signature->public_key_verify)(key->context,
                                              signature,
                                              signature_len,
                                              TRUE, data, data_len,
                                              key->signature->hash_def);
}

DLLEXPORT Boolean DLLCALLCONV
ssh_public_key_verify_signature_with_digest(SshPublicKey key,
                                            const unsigned char *signature,
                                            size_t signature_len,
                                            const unsigned char *digest,
                                            size_t digest_len)
{
  if (key->signature == NULL)
    return FALSE;

  return (*key->signature->public_key_verify)(key->context,
                                              signature, signature_len,
                                              FALSE, digest, digest_len,
                                              key->signature->hash_def);
}

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_signature_input_len(SshPrivateKey key)
{
  if (key->signature == NULL)
    return 0;
  
  return (*key->signature->private_key_max_signature_input_len)(key->context);
}

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_signature_output_len(SshPrivateKey key)
{
  if (key->signature == NULL)
    return 0;
  
  return (*key->signature->private_key_max_signature_output_len)(key->context);
}

/* Return the maximal lenght of bytes which may be decrypted with this
   private key. The result is queried from the corresponding private key
   cryptosystem package with a type-specific function. */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_decrypt_input_len(SshPrivateKey key)
{
  if (key->encryption == NULL)
    return 0;

  return (*key->encryption->private_key_max_decrypt_input_len)(key->context);
}

/* Similar to the previous function except this will return the maximum
   output lenght with decryption. */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_decrypt_output_len(SshPrivateKey key)
{
  if (key->encryption == NULL)
    return 0;
  
  return (*key->encryption->private_key_max_decrypt_output_len)(key->context);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_decrypt(SshPrivateKey key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        unsigned char *plaintext_buffer,
                        size_t ssh_buffer_len,
                        size_t *plaintext_length_return)
{
  if (key->encryption == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*key->encryption->private_key_decrypt)(key->context,
                                              ciphertext,
                                              ciphertext_len,
                                              plaintext_buffer,
                                              ssh_buffer_len,
                                              plaintext_length_return,
                                              key->encryption->hash_def))

    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_sign(SshPrivateKey key,
                     const unsigned char *data,
                     size_t data_len,
                     unsigned char *signature_buffer,
                     size_t ssh_buffer_len,
                     size_t *signature_length_return,
                     SshRandomState state)
{
  if (key->signature == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*key->signature->private_key_sign)(key->context,
                                          TRUE, data, data_len,
                                          signature_buffer, ssh_buffer_len,
                                          signature_length_return,
                                          state,
                                          key->signature->hash_def))
    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}


#if 0
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_sign(SshPrivateKey key,
                     const unsigned char *data,
                     size_t data_len,
                     unsigned char **signature_buffer,
                     size_t *ssh_buffer_length,
                     SshRandomState state)
{
  if (key->signature == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*key->signature->private_key_sign)(key->context,
                                          TRUE, data, data_len,
                                          signature_buffer, ssh_buffer_length,
                                          state,
                                          key->signature->hash_def))
    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}
#endif






DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_sign_digest(SshPrivateKey key,
                            const unsigned char *digest,
                            size_t digest_len,
                            unsigned char *signature_buffer,
                            size_t ssh_buffer_len,
                            size_t *signature_length_return,
                            SshRandomState state)
{
  if (key->signature == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*key->signature->private_key_sign)(key->context,
                                          FALSE, digest, digest_len,
                                          signature_buffer, ssh_buffer_len,
                                          signature_length_return,
                                          state,
                                          key->signature->hash_def))
    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}

/* Diffie-Hellman key exchange method. */

DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_diffie_hellman_setup_max_output_length(SshPkGroup group)
{
  if (group->diffie_hellman == NULL)
    return 0;
  return (*group->diffie_hellman->
          diffie_hellman_exchange_max_length)(group->context);
}

DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_diffie_hellman_agree_max_output_length(SshPkGroup group)
{
  if (group->diffie_hellman == NULL)
    return 0;
  return (*group->diffie_hellman->
          diffie_hellman_secret_value_max_length)(group->context);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_diffie_hellman_setup(SshPkGroup group,
                                  void **secret,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  size_t *return_length,
                                  SshRandomState state)
{
  if (group->diffie_hellman == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*group->diffie_hellman->diffie_hellman_setup)(group->context,
                                                     secret,
                                                     exchange_buffer,
                                                     exchange_buffer_length,
                                                     return_length,
                                                     state))
    return SSH_CRYPTO_OK;

  return SSH_CRYPTO_OPERATION_FAILED;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_diffie_hellman_agree(SshPkGroup group,
                                  void *secret,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  unsigned char *secret_value_buffer,
                                  size_t secret_value_buffer_length,
                                  size_t *return_length)
{
  if (group->diffie_hellman == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*group->diffie_hellman->
       diffie_hellman_agree)(group->context,
                             secret,
                             exchange_buffer,
                             exchange_buffer_length,
                             secret_value_buffer,
                             secret_value_buffer_length,
                             return_length))
    return SSH_CRYPTO_OK;
  return SSH_CRYPTO_OPERATION_FAILED;
}

/* Unified Diffie-Hellman. */

DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_unified_diffie_hellman_agree_max_output_length(SshPkGroup group)
{
  if (group->diffie_hellman == NULL)
    return 0;
  return (*group->diffie_hellman->
          udh_secret_value_max_length)(group->context);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_unified_diffie_hellman_agree(SshPublicKey public_key,
                                          SshPrivateKey private_key, 
                                          void *secret,
                                          unsigned char *exchange_buffer,
                                          size_t exchange_buffer_length,
                                          unsigned char *secret_value_buffer,
                                          size_t secret_value_buffer_length,
                                          size_t *return_length)
{
  if (private_key->diffie_hellman == NULL ||
      public_key->diffie_hellman == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((*private_key->diffie_hellman->
       udh_agree)(public_key->context,
                  private_key->context,
                  secret,
                  exchange_buffer,
                  exchange_buffer_length,
                  secret_value_buffer,
                  secret_value_buffer_length,
                  return_length))
    return SSH_CRYPTO_OK;
  return SSH_CRYPTO_OPERATION_FAILED;
}

/* ... more to come. */
