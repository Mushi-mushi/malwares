/*

Public interface to the SSH cryptographic library.  This file defines
the functions and interfaces available to applications.

Author: Mika Kojo <mkojo@ssh.fi>
        Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1995-1998 SSH Communications Security Inc, Finland.
                        All rights reserved.

*/

/*
 * $Log: sshcrypt.h,v $
 * $EndLog$
 */

#ifndef SSHCRYPT_H
#define SSHCRYPT_H

/* Status/error codes. */

typedef enum
{
  /* Operation was successfully completed. */
  SSH_CRYPTO_OK                 = 0,

  /* The algorithm/key is not supported. */
  SSH_CRYPTO_UNSUPPORTED        = 1,

  /* Given data too long for this operation. */
  SSH_CRYPTO_DATA_TOO_LONG      = 2,

  /* Private key import failed because of invalid passphrase. */
  SSH_CRYPTO_INVALID_PASSPHRASE = 3,

  /* When encrypting/decrypting with a block cipher, the input block's
     length is not a multiple of the ciphers block length. */
  SSH_CRYPTO_BLOCK_SIZE_ERROR   = 4,

  /* The supplied key is too short. */
  SSH_CRYPTO_KEY_TOO_SHORT      = 5,

  /* Encryption/decryption failed (wrong key). */
  SSH_CRYPTO_OPERATION_FAILED   = 6, 

  /* Identifier given is not supported. */
  SSH_CRYPTO_UNSUPPORTED_IDENTIFIER = 7,

  /* Given scheme name was not recognized, i.e. not supported. */
  SSH_CRYPTO_SCHEME_UNKNOWN = 8,

  /* Group type given was not recognized. */
  SSH_CRYPTO_UNKNOWN_GROUP_TYPE = 9,
  /* Key type given was not recognized. */
  SSH_CRYPTO_UNKNOWN_KEY_TYPE = 10,
  
  /* Given key context was uninitialized. Please note, that library does
     not, nor cannot, always verify that key was initialized properly.
     However, to avoid any problems one should not give NULL keys to
     functions that clearly cannot them handle. I.e. functions that
     use information in keys should not be called with NULL keys. */
  SSH_CRYPTO_KEY_UNINITIALIZED = 11,
  
  /* Key blob contained information that could not be parsed, i.e. it
     probably is corrupted (or of newer/older version). */
  SSH_CRYPTO_CORRUPTED_KEY_FORMAT = 12,

  /* XXX Debugging message. To be removed. */
  SSH_CRYPTO_LIBRARY_CORRUPTED  = 13
} SshCryptoStatus;

/* Converts the status message to a string. */
DLLEXPORT const char * DLLCALLCONV
ssh_crypto_status_message(SshCryptoStatus status);

/* Crypto library progress monitoring. Those operations that are time
   consuming such as the key generation (in particular prime search),
   one can get progress information by registering a progress function.

   Following operations are defined which are time consuming, and thus
   need progress monitoring. */

typedef enum
{
  SSH_CRYPTO_PRIME_SEARCH
} SshCryptoProgressID;

/* Progress monitor function is given an id of the operation type and
   a time index which is an increasing counter indicating that library
   is working on something. Context is given which actually is created by
   a call to init function and freed afterwards by a call to free
   function. */

typedef void (*SshCryptoProgressMonitor)(SshCryptoProgressID id,
                                         unsigned int time_value,
                                         void *progress_context);

/* To register call this function with the progress monitor and a context
   structure which will be given to the function when called. To
   unregister the progress monitor this function should be called
   with NULL parameters. progress_context can be NULL, in case
   monitor_function will be passed a NULL progress_context. */

DLLEXPORT void DLLCALLCONV
ssh_crypto_library_register_progress_func(SshCryptoProgressMonitor
                                          monitor_function,
                                          void *progress_context);

/********************* Pseudo-Random numbers ******************************/

typedef struct SshRandomStateRec *SshRandomState;

/* Initializes a random number generator.  The generator is used as follows:
     1. Allocate the generator.
     2. Add a sufficient amount of randomness (noise).
     3. Stir noise into the generator..
     4. Use the generator to obtain random numbers. It is recommended to
        periodically add more noise during normal use.
     5. Free the generator when no longer needed.

   Note that it is very important to add enough noise into the generator
   to get good quality random numbers.

   A commonly used technique is to collect a large amount of true randomness
   when the program is first started, and save a few hundred bits worth of
   randomness (obtained by calling ssh_random_get_byte repeatedly) in
   a file, and add that noise into the pool whenever the program is started
   again.  Note that it is also important to update the saved random seed
   every time it is used.

   This function never fails.  If an error is encountered, this calls
   ssh_fatal(). */

DLLEXPORT SshRandomState DLLCALLCONV ssh_random_allocate(void);

/* Mixes the bytes from the buffer into the pool.  The pool should be stirred
   after a sufficient amount of noise has been added. */

DLLEXPORT void DLLCALLCONV
ssh_random_add_noise(SshRandomState state, const void *buf,
                     size_t bytes);

/* Stirs the pool of randomness, making every bit of the internal state
   depend on every other bit.  This should be called after adding new
   randomness.  The stirring operation is irreversible, and a few bits of
   new randomness are automatically added before every stirring operation
   to make it even more impossible to reverse. */

DLLEXPORT void DLLCALLCONV ssh_random_stir(SshRandomState state);

/* Returns a random byte.  Stirs the pool if necessary.  If this is called
   repeatedly, a small of new environmental noise will automatically be
   acquired every few minutes. */

DLLEXPORT unsigned int DLLCALLCONV ssh_random_get_byte(SshRandomState state);

/* Zeroes and frees any data structures associated with the random number
   generator.  This should be called when the state is no longer needed to
   remove any sensitive data from memory. */

DLLEXPORT void DLLCALLCONV ssh_random_free(SshRandomState state);

/*********************** Hash functions ***********************************/

typedef struct SshHashRec *SshHash;

/* Maximum digest length that may be output by any hash function. */
#define SSH_MAX_HASH_DIGEST_LENGTH   32

/* Returns a comma-separated list of supported hash functions names.
   The caller must free the returned value with ssh_xfree(). */
DLLEXPORT char * DLLCALLCONV
ssh_hash_get_supported(void);

/* Returns TRUE or FALSE depending whether the hash function called
   "name" is supported with this version of crypto library. */
DLLEXPORT Boolean DLLCALLCONV
ssh_hash_supported(const char *name);

/* Allocates and initializes a hash context. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_hash_allocate(const char *name, SshHash *hash);

/* Free hash context. */
DLLEXPORT void DLLCALLCONV
ssh_hash_free(SshHash hash);

/* Resets the hash context to its initial state. */
DLLEXPORT void DLLCALLCONV
ssh_hash_reset(SshHash hash);

/* Get the ASN.1 Object Identifier of the hash, if available. Returns the
   OID in 'standard' form e.g. "1.2.3.4". Returns NULL if a OID is not
   available. The returned value points to internal constant data and
   need not be freed. */
DLLEXPORT const char * DLLCALLCONV
ssh_hash_asn1_oid(SshHash hash);

/* Get the ISO/IEC dedicated hash number, if available. The value
   returned, is an octet containing the dedicated hash number. If the
   returned value is 0, no number is available.
   XXX this might change in future. */
DLLEXPORT unsigned char DLLCALLCONV
ssh_hash_iso_identifier(SshHash hash);

/* Get the digest length of the hash. */
DLLEXPORT size_t DLLCALLCONV
ssh_hash_digest_length(SshHash hash);

/* Get input block size (used for hmac padding). */
DLLEXPORT size_t DLLCALLCONV
ssh_hash_input_block_size(SshHash hash);

/* Updates the hash context by adding the given text. */
DLLEXPORT void DLLCALLCONV
ssh_hash_update(SshHash hash, const void *buf, size_t len);

/* Outputs the hash digest. */
DLLEXPORT void DLLCALLCONV
ssh_hash_final(SshHash hash, unsigned char *digest);

/* Hashes one buffer with selected hash type and returns the digest.
   This calls ssh_fatal() if called with an invalid type. */
DLLEXPORT void DLLCALLCONV
ssh_hash_of_buffer(const char *type,
                   const void *buf, size_t len,
                   unsigned char *digest);

/************************* Secret key cryptography ************************/

/* Type used to represent a cipher object.  The exact semantics of the
   cipher depend on the encryption algorithm used, but generally the
   cipher object will remember its context (initialization vector, current
   context for stream cipher) from one encryption to another. */
typedef struct SshCipherRec *SshCipher;

/* There are commonly used cipher algorithms that allow usage of
   variable length keys. This defines the length that is the minimum
   which will be allowed by the crypto library, for those ciphers.
   However, application can indeed give keys that are shorter, but
   when ever crypto library is to expand keys etc. it always uses
   atleast this amount of key data.
   
   Currently 40 bits of key is the minimum. 
   */
#define SSH_CIPHER_MINIMAL_KEY_LENGTH 5

/* Maximum size of a cipher block for block ciphers, in bytes. */
#define SSH_CIPHER_MAX_BLOCK_SIZE       32

/* Maximum size of the iv (initialization vector) for block ciphers in chained
   modes, in bytes. */
#define SSH_CIPHER_MAX_IV_SIZE          32

/* Returns a comma-separated list of cipher names.  The name may be of the
   format (e.g.) "des-cbc" for block ciphers.  The caller must free the
   returned list with ssh_xfree(). */
DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported(void);

/* Same as ssh_cipher_get_supported but aliases are excluded from
   the list. */
DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported_native(void);

/* Returns TRUE or FALSE depending whether the cipher called "name" is
   supported with this version of crypto library. */
DLLEXPORT Boolean DLLCALLCONV
ssh_cipher_supported(const char *name);

/* Get `canonialized' name for cipher.  If cipher name is already
   one of the native ciphers, return the copy of the given name.
   If cipher is not supported, return NULL

   The returned string have to be freed with ssh_xfree(). */
DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_native_name(const char *name);

/* Allocates and initializes a cipher of the specified type and mode.
   The cipher is keyed with the given key.  For_encryption should be true
   if the cipher is to be used for encrypting data, and false if it is to
   be used for decrypting.  The initialization vector for block ciphers is
   set to zero.

   If the key is too long for the given cipher, the key will be
   truncated.  If the key is too short, SSH_CRYPTO_KEY_TOO_SHORT is
   returned.

   This returns SSH_CRYPTO_OK on success. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate(const char *type,
                    const unsigned char *key,
                    size_t keylen,
                    Boolean for_encryption,
                    SshCipher *cipher);

/* Allocates and initializes a new cipher.  The key is set by
   computing the MD5 checksum of the given passphrase, and using the
   MD5 hash as the key to ssh_cipher_allocate.  If 128 bits is too short
   for the cipher, the key will be expanded by repeatedly appending MD5 of
   the key so far until enough keying material is available. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_with_passphrase(const char *type,
                                    const char *passphrase,
                                    Boolean for_encryption,
                                    SshCipher *cipher);

/* Allocates and initializes a new cipher. Tells the cipher to check for
   weak keys, and returns an error if weak key was given.

   XXX To be really implemented later, at this time no checks are done. If
   testing is needed then changes to cipher interface needs to be done
   at lower level and it demands some discussion. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_and_test_weak_keys(const char *type,
                                       const unsigned char *key,
                                       size_t keylen,
                                       Boolean for_encryption,
                                       SshCipher *cipher);

/* Clears and frees the cipher from main memory.  The cipher object becomes
   invalid, and any memory associated with it is freed. */

DLLEXPORT void DLLCALLCONV ssh_cipher_free(SshCipher cipher);

/* Returns the native algorithm name of the allocated cipher.
   Returned string has to be freed with ssh_xfree. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_name(SshCipher cipher);

/* Query for the key length needed for a cipher. This returns the
   number of bytes that a key of the given cipher consists of. If the
   cipher can utilize variable length keys (i.e., all lengths go), the
   function returns zero. */
DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_key_length(const char *name);

/* Returns the block length of the cipher, or 1 if it is a stream cipher.
   The returned value will be at most SSH_CIPHER_MAX_BLOCK_SIZE. */
DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_block_length(SshCipher cipher);

/* Returns the length of the initialization vector of the cipher in
   bytes, or 1 if it is a stream cipher.  The returned value will be
   at most SSH_CIPHER_MAX_IV_SIZE. */
DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_iv_length(SshCipher cipher);

/* Sets the initialization vector of the cipher.  This is only
   meaningful for block ciphers used in one of the feedback/chaining
   modes.  The default initialization vector is zero (every bit 0);
   changing it is completely optional (although recommended). */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_set_iv(SshCipher cipher,
                  const unsigned char *iv);

/* Gets the initialization vector of the cipher.  This is only
   meaningful for block ciphers used in one of the feedback/chaining
   modes.  The default initialization vector is zero (every bit 0);
   changing it is completely optional.  The returned value will be
   at most SSH_CIPHER_MAX_IV_SIZE bytes. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_get_iv(SshCipher cipher,
                  unsigned char *iv);

/* Encrypts/decrypts data (depending on the for_encryption flag given when the
   SshCipher object was created).  Data is copied from src to dest while it
   is being encrypted/decrypted.  It is permissible that src and dest be the
   same buffer; however, partial overlap is not allowed.  For block ciphers,
   len must be a multiple of the cipher block size (this is checked); for
   stream ciphers there is no such limitation.

   If the cipher is used in a chaining mode or it is a stream cipher, the
   updated initialization vector or context is passed from one
   encryption/decryption call to the next.  In other words, all blocks
   encrypted with the same context form a single data stream, as if they
   were all encrypted with a single call.  If you wish to encrypt each
   block with a separate context, you must create a new SshCipher object
   every time (or, for block ciphers, you can manually set the initialization
   vector before each encryption). */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_transform(SshCipher cipher,
                     unsigned char *dest,
                     const unsigned char *src,
                     size_t len);

/* This performs a combined ssh_cipher_set_iv, ssh_cipher_transform,
   and ssh_cipher_get_iv sequence (except that the iv stored in the
   cipher context is not actually changed by this sequence).  This
   function can be safely called from multiple threads concurrently
   (i.e., the iv is only stored on the stack).  This function can only
   be used for block ciphers.  The buffer for iv should be
   SSH_CIPHER_MAX_IV_SIZE bytes. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_transform_with_iv(SshCipher cipher,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len,
                             unsigned char *iv);


/*********************** Mac functions ************************************/

typedef struct SshMacRec *SshMac;

/* General mac (message authentication code) functions, these are to
   allow transparent use of all SSH supported mac types.

   Allocate mac to be used with ssh_mac_allocate. The actual mac calculation
   can be performed with first calling ssh_mac_start, then n times
   ssh_mac_update and the digest can be received with ssh_mac_final function.
   Notice that the digest must be reallocated and of correct length. */

/* Returns a comma-separated list of supported mac types.  The caller
   must return the list with ssh_xfree(). */
DLLEXPORT char * DLLCALLCONV
ssh_mac_get_supported(void);

/* Returns TRUE or FALSE depending whether the cipher called "name" is
   supported with this version of crypto library. */
DLLEXPORT Boolean DLLCALLCONV
ssh_mac_supported(const char *name);

/* Allocate mac for use in session */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_mac_allocate(const char *type,
                 const unsigned char *key, size_t keylen,
                 SshMac *mac);

/* Free the mac. */
DLLEXPORT void DLLCALLCONV
ssh_mac_free(SshMac mac);

/* Get the length of mac digest.  The maximum length is
   SSH_MAX_HASH_DIGEST_LENGTH. */
DLLEXPORT size_t DLLCALLCONV
ssh_mac_length(SshMac mac);

/* Reset the mac to its initial state.  This should be called before
   processing a new packet/message. */
DLLEXPORT void DLLCALLCONV
ssh_mac_start(SshMac mac);

/* Update the mac by adding data from the given buffer. */
DLLEXPORT void DLLCALLCONV
ssh_mac_update(SshMac mac, const unsigned char *data, size_t len);

/* Get the resulting MAC.  */
DLLEXPORT void DLLCALLCONV
ssh_mac_final(SshMac mac, unsigned char *digest);

/* Mac info manipulation. With mac info we simply mean the information
   needed to construct a mac out of something else, such as a hash
   function. This operation is useful in situations where you have the
   basic ingredients such as a hash function, and want to explicitly
   derive mac function out of it.

   At the moment only derivation from hash functions is allowed. It seems
   unlikely that direct derivation from other classes of functions such
   as block ciphers will be needed. If such occasion arises one can
   usually transform the cipher into a hash function first and then
   use this transformation given here.

   XXX The interface uses 3 functions, could it be done in just one?
       Probably, but perhaps there will be some occasions where this
       style is useful?
   */

/* We support two types at the moment (and many variations). */
typedef enum
{
  /* This denotes the HMAC type. */
  SSH_MAC_TYPE_HMAC,
  /* This denotes the group of Key - Data - Key (KDK) macs. */
  SSH_MAC_TYPE_KDK
} SshMacType;

/* Derives the mac info from the hash context. Returns NULL if failed.
   Failure can be caused by incorrect hash or mac type. */
DLLEXPORT void * DLLCALLCONV
ssh_mac_info_derive_from_hash(SshHash hash,
                              SshMacType type);

/* Free the mac info, which is denoted by a void pointer. This function
   should be called only if the mac allocation with info fails (that is
   ssh_mac_allocate_with_info). */
DLLEXPORT void DLLCALLCONV
ssh_mac_info_free(void *mac_info);

/* Build a SshMac context out of the mac info and a key. The mac info will
   be included into the the mac definition returned. Also it will be
   freed when the mac is freed. Thus you should not free it with the
   ssh_mac_info_free function.

   Function returns NULL if fails.

   The returned SshMac context is equivalent to the usual contexts,
   and should be handled in similar manner. Of course, you can derive
   mac functions using this system which are not defined in the
   supported mac function lists.

   As mentioned before the mac_info cannot be used again after call to
   this routine. 
   */
DLLEXPORT SshMac DLLCALLCONV
ssh_mac_allocate_with_info(const void *mac_info, 
                           unsigned char *key,
                           size_t keylen);


/************************* Public key cryptography ************************/

/* SSH public key vararg list format identifiers. Basic idea is to allow
   application using this interface to get hold on the actual private and
   public keys. Only some of the operations need to be known to use this
   interface.

   Not all combinations of identifiers are supported. Some care should
   be exercised when making combinations. The use of these identifiers
   is very special behaviour and should be performed only when all the
   power of the interface is to be used.

   Note: most input will be given in SshInt's because it is reasonably
         convenient way of handling large strings of bits. However,
         not all values are integers, nor natural numbers. You should
         not assume that any SshInt you get can be used for reasonable
         computations without knowledge of the meaning of the actual
         value. 
   
   */

typedef enum
{
  /* Identifier to mark the end of the vararg list. As always, vararg list
     should be written with care. It could be a good idea to write simple
     wrappers around the most used ways of using this library (e.g. macros). */
  SSH_PKF_END,

  /* Identifiers that are of most use. */
  
  /* Basic operations for generation of new key or group. */

  /* Size of the key in bits. This usually means the number of bits in the
     integer or polynomial modulus.

     When generating:          unsigned int

         Size in bits (depends on algorithm specific details).
     
     When reading information: unsigned int *

         As above.
     */
  SSH_PKF_SIZE,

  /* The entropy in bits used for randomizer generation. More simply
     said, the parameter tells how many bits of random data will be
     used for the generation of the randomizer. The effect of using
     less than the groups size is less security, although usually
     faster speed in operations using randomizers.

     Don't use this option unless:
       1. You _know_ that the reduction (yes, you can only reduce the
          entropy) is not making your product unsecure.
       2. You need the extra speed up badly.

     When genererating:       unsigned int 

        Entropy in bits. Usually it will be rounded up to nearest
        multiple of 8. This happens within this library.

     When reading information: unsigned int *

        The actual bit count used to generate the entropy will be
        outputed. 
     */
  SSH_PKF_RANDOMIZER_ENTROPY,
  
  /* The library has defined some predefined groups for some of the
     algorithms. Using them speeds up the private key generation. However,
     randomly generated groups might make attackers job a little bit
     harder. However, note that randomly generated groups cannot be
     verified as rigorously as these predefined groups. Thus using them
     is usually safest.

     When generating:          const char *

        Name of the predefined group one wants to use. See
        ssh_public_key_get_predefined_groups() for more information.
     
     When reading information: const char **

        Returns a pointer to a string. This need not be freed later.
     */
     
  SSH_PKF_PREDEFINED_GROUP,

  /* Advanced identifiers. */

  /* Key type of the public/private key or group. */

  /* When generating a key or group one must give the key or group type.
     One can also get the type out of the key with these identifiers.

     When reading information: const char **

       Returns a pointer to a constant string. 

     Following key types are used:

       if-modn:

         All schemes based on integer factorization.

       dl-modp:

         All schemes based on discrete logarithm modulo p.

       ec-modp:

         Schemes based on elliptic curves over integers (mod p)
         discrete logarithm problem.

       ec-gf2n:

         Schemes based on elliptic curves over Galois field GF(2^n)
         discrete logarithm problem.
       
     */
  SSH_PKF_KEY_TYPE,
  
  /* XXX This is not yet supposed to be used. One can use created
     parameters, i.e. public key group, to initialize the set of
     parameters for suitable public key or private key. */
  SSH_PKF_GROUP,

  /* XXX This flag is not yet supported. It should be used, when
     implemented, to do some computation to verify that given parameters.
     That is, we can check that parameters that were acquired from
     third party, are suitably valid. This should notice most flawed
     parameters. */
  SSH_PKF_VERIFY, 

  
  /* Scheme types defined. */

  /* This library divides public key methods into scheme types. For example
     we have

        signature schemes
        encryption schemes
        key exchange schemes

     and actually the key exchange schemes are here divided into their
     basic algorithms.

     Following identifiers can be used to select some particular algorithm
     of the scheme type.

     When generating:           const char *

       The algorithm name. See ssh_public_key_get_supported() for more
       information.

     When reading information:  const char **

       Returns a pointer to a string. It need not be freed.

     */

  /* Signature scheme type */
  SSH_PKF_SIGN,
  /* Encryption scheme type */
  SSH_PKF_ENCRYPT,
  /* Diffie-Hellman key exchange scheme type. This includes also
     the Unified approach. */
  SSH_PKF_DH,
  
  /* Specific operations for each key and group type. */

  /* This identifier denotes the explicit public key in numeric form. For
     different key types it might be given in different forms.
  
       dl-modp:

          generation:  SshInt *
          reading:     SshInt *

       ec-modp:

          generation:  SshInt *, SshInt *
          reading:     SshInt *, SshInt *

          The comma denotes that we mean a pair or values. E.g. the first
          one is the x co-ordinate and the second y co-ordinate. We
          assume that the point is valid. 

       ec-gf2n:

          generation: SshInt *, SshInt *
          reading:    SshInt *, SshInt *
          
     */
     
  SSH_PKF_PUBLIC_Y,

  /* This identifier denotes the explicit secret key in numeric form.

       dl-modp:

         generation:   SshInt *
         reading:      SshInt *

       ec-modp:

         generation:   SshInt *
         reading:      SshInt *

       ec-gf2n:

         generation:   SshInt *
         reading:      SshInt *

     */
  
  SSH_PKF_SECRET_X,

  /* This identifier has a dual meaning. Although it always should be
     a prime number. However, it is defined for all supported key types.

     For integer factorization (mainly RSA) based systems this identifier
     means the other of the primes for the modulus.
     
       if-modn:

         generation:    SshInt *
         reading:       SshInt *

     For the discrete logarithm problem based methods this identifier
     means the integer field modulus.
         
       dl-modp:

         generation:    SshInt *
         reading:       SshInt *
       
       ec-modp:

         generation:    SshInt *
         reading:       SshInt *

       ec-gf2n:

         generation:    SshInt *
         reading:       SshInt *

     */
  
  SSH_PKF_PRIME_P,

  /* This identifier is in princible equivalent to SSH_PKF_PRIME_P, but
     instead of being in integer domain we are working with polynomials
     with terms taken (mod 2). E.g. this is the irreducible polynomial
     for the Galois field GF(2^n).

       ec-gf2n:

         generation:   SshInt *
         reading:      SshInt *

    */
     
  SSH_PKF_IRREDUCIBLE_P,
  
  /* This identifier has a dual meaning. Although it always should be
     a prime number.

     For integer factorization based systems this identifier means the
     other of the prime for the modulus (other is the SSH_PKF_PRIME_P).

       if-modn:

         generation:    SshInt *
         reading:       SshInt *

     For the discrete logarithm problem bases system this identifier
     means the order of the group in which computation occurs.

       dl-modp:

         generation:    SshInt *
         reading:       SshInt *

       ec-modp:

         generation:    SshInt *
         reading:       SshInt *

       ec-gf2n:

         generation:    SshInt *
         reading:       SshInt *

     */
  
  SSH_PKF_PRIME_Q,

  /* The generator for discrete logarithm based methods.

       dl-modp:

         generation:   SshInt *
         reading:      SshInt *

       ec-modp:

         generation:   SshInt *, SshInt *
         reading:      SshInt *, SshInt *

       Here we denote by comma the fact that you are supposed to give
       two values, a pair, as input. The first component will be x, and
       the second y, value of the point returned or used.

       ec-gf2n:

         generation:   SshInt *, SshInt *
         reading:      SshInt *, SshInt *
         

     In general generator is a value which generates the set of numbers
     over which we perform our crypto operations.
       
     */
  
  SSH_PKF_GENERATOR_G,


  /* Following three identifiers are only defined for integer
     factorization based methods.

       if-modn:

         generation:    SshInt *
         reading:       SshInt *

     Currently implemented is the RSA which used n = pq and e = d^1 (mod n).
         
     */
  
  SSH_PKF_MODULO_N,


  /* Value for public exponent in e.g. RSA style methods.

       if-modn:

         generation:    SshInt *
         reading:       SshInt *

       In context of RSA this value will set the public exponent
       explicitly to some value or make sure that the value set is the
       next larger value possible. (However, if other parameters are
       explicitly given such as SSH_PKF_SECRET_D then it will be used
       to generate public exponent). 

       */
     
  SSH_PKF_PUBLIC_E,
  
  /* Value for secret exponent in e.g. RSA style methods.

       if-modn:

         generation:     SshInt *
         reading:        SshInt *

       In RSA this value has priority over public exponent. Given this
       value and primes p and q, all the RSA parameters can be
       deduced.

       */
  SSH_PKF_SECRET_D,
  
  /* This value is used mainly in RSA.

       if-modn:

         generation:     SshInt *
         reading:        SshInt *

       This value can be excluded because it is automatically computed
       within the parameter making utility. Although, if given among all
       other parameters it will be used as is.

       */
  SSH_PKF_INVERSE_U,
  
  /* These four definitions are only defined for elliptic curve methods.

       ec-modp:

         generation:       Boolean
         reading:          Boolean *

       ec-gf2n:

         generation:   Boolean 
         reading:      Boolean *

     Point compression can be applied when ever a point is linearized to
     a octet buffer. However, it takes time to reconstruct and thus is
     not suggested. Default is no point compression.
         
      */
     
  SSH_PKF_POINT_COMPRESS,

  /*   ec-modp:

         generation:       SshInt *
         reading:          SshInt *

       ec-gf2n:

         generation:   SshInt *
         reading:      SshInt *

       The number of points that lie of elliptic curve your are defining,
       or reading. This is not important for the working of the system,
       only that you can make sure that your parameters are secure. 
       
         */
  
  SSH_PKF_CARDINALITY,

  /*   ec-modp:

         generation:       SshInt *
         reading:          SshInt *

       ec-gf2n:

         generation:   SshInt *
         reading:      SshInt *

       The another number which is used to define the elliptic curve.
         
         */
  SSH_PKF_CURVE_A,
  /*   ec-modp:

         generation:       SshInt *
         reading:          SshInt *

       ec-gf2n:

         generation:   SshInt *
         reading:      SshInt *

       The another number which is used to define the elliptic curve. 
         
         */
  SSH_PKF_CURVE_B
  
} SshPkFormat;

/* We want to fix the minimum entropy to some reasonably large number,
   however, we don't want it to be too large. 160 bits have been
   mentioned in some places to be a good start. You should probably use
   > 200 bits for more conservative applications. More entropy you
   give the more secure the system is, however, the public key
   parameters define the largest number of bits possible. */
#define SSH_RANDOMIZER_MINIMUM_ENTROPY 160

/* A data structure for representing a public key group in main memory. */
typedef struct SshPkGroupRec *SshPkGroup;

/* A data structure for representing a public key in main memory. */
typedef struct SshPublicKeyRec *SshPublicKey;

/* A data structure for describing a private key in memory. */
typedef struct SshPrivateKeyRec *SshPrivateKey;

/* Function to get a comma separated list of all supported predefined
   groups of this particular key type. */

DLLEXPORT char * DLLCALLCONV
ssh_public_key_get_predefined_groups(const char *key_type);

/* Returns a tree-like list, if you like, of public key algorithms
   supported. Format is defined as

     key-type{scheme-type{algorithm,...},...},...

   for example

     if-modn{sign{rsa-pkcs1-md5},encrypt{rsa-pkcs1-none}}
     
   such a name can be parsed with SshNameTree routines. See namelist.h for
   further details.
   This format will contain all algorithms supported in order where
   the first is the preferred one. 
     
   The caller must free the returned string with ssh_xfree().
   */

DLLEXPORT char * DLLCALLCONV ssh_public_key_get_supported(void);

/* Function to get explicitly the name of the public key. Returns the name
   in a ssh_xmalloc allocated string. This string should be freed after
   use, by the application with call to ssh_xfree.

   The name returned is the full name extended with scheme fields. To get
   just the key type use ssh_public_key_get_info. 
   */
DLLEXPORT char * DLLCALLCONV
ssh_public_key_name(SshPublicKey key);

/* Function to get explicitly the name of the private key. Returns the name
   in a ssh_xmalloc allocated string. This string should be freed after
   use, by the application with call to ssh_xfree.

   The name returned is the full name extended with scheme fields. To get
   just the key type use ssh_private_key_get_info. 
   */
DLLEXPORT char * DLLCALLCONV
ssh_private_key_name(SshPrivateKey key);

/* Function to get explicitly the name of the public key
   group. Returns the name in a ssh_xmalloc allocated string. This
   string should be freed after use, by the application with call to
   ssh_xfree.

   The name returned is the full name extended with scheme fields. To get
   just the key type use ssh_pk_group_get_info.  */
DLLEXPORT char * DLLCALLCONV
ssh_pk_group_key_name(SshPkGroup group);

/* Define a public key from predefined parameters. This function has its
   most important meaning in reconstructing values from certificates,
   however in general this function can be used to convert other public
   keys into SSH internal format. Usage is similar to
   ssh_private_key_generate() in that the vararg list uses the
   SshPkFormat idea. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_define(SshPublicKey *key, const char *key_type, ...);

/* Allocates and initializes a public key object from the contents of
   the buffer.  The buffer has presumably been created by
   ssh_public_key_export. Returns SSH_CRYPTO_OK, if everything went
   fine. In such a case, the public key will be written to *key.
   Otherways *key might contain garbage. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_import(const unsigned char *buf,
                      size_t len,
                      SshPublicKey *key);

/* Create a public key blob from an SshPublicKey. Returns
   SSH_CRYPTO_OK, if everything went fine. In such a case, *buf will
   be set to point to dynamically allocated memory which contains the
   blob, and *length_return to the length of the blob.  The caller must free
   buf with ssh_xfree(). */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_export(SshPublicKey key,
                      unsigned char **buf,
                      size_t *length_return);


/* This function creates a public key blob (or linearization of the key).
   Returns SSH_CRYPTO_OK if everything went fine. In such a case *buf will
   be set to point to a dynamically allocated memory which contains the
   blob, and *length_return to the length of the blob. The caller must
   free the buf with ssh_xfree().

   In effect, the key doesn't contain information about the schemes and
   thus the application must save them without this function. 
   */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_export_canonical(SshPublicKey key,
                                unsigned char **buf,
                                size_t *length_return);

/* Copy public key from 'key_src' to 'key_dest'. Returns SSH_CRYPTO_OK,
   if everything went fine. This copying is explicit, operation on other
   doesn't affect the other. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_copy(SshPublicKey key_src,
                    SshPublicKey *key_dest);

/* Clears and frees the public key. Cannot fail. */

DLLEXPORT void DLLCALLCONV ssh_public_key_free(SshPublicKey key);

/* Returns the maximum number of bytes that can be encrypted using this key.
   If this key is not capable of encryption (it is for signature verification
   only), this returns 0. */

DLLEXPORT size_t DLLCALLCONV
ssh_public_key_max_encrypt_input_len(SshPublicKey key);

/* Returns the size of the buffer required for encrypting data with this key.
   If the key is not capable of encryption, this returns 0. */

DLLEXPORT size_t DLLCALLCONV
ssh_public_key_max_encrypt_output_len(SshPublicKey key);

/* Encrypts data using the key.  The caller must allocate a large
   enough buffer to contain the encrypted result.  The data to be
   encrypted will be padded according to the current encoding and
   algorithm type.

   The ciphertext_buffer_len argument is only used to verify that the buffer
   really is large enough.

   The function returns SSH_CRYPTO_OK, if everything went fine. Then
   *ciphertext_len_return contains the number of bytes actually
   written to ciphertext_buffer. For some PKCSs, this will always be
   ssh_public_key_max_encrypt_output_len(key). If the return value is
   not SSH_CRYPTO_OK, ciphertext_buffer and *ciphertext_len_return
   might contain garbage. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_encrypt(SshPublicKey key,
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char *ciphertext_buffer,
                       size_t ciphertext_buffer_len,
                       size_t *ciphertext_len_return,
                       SshRandomState random_state);

/* Verifies that the given signature matches with the given data.  The
   exact relationship of the data to the signature depends on the
   algorithm and encoding used for the key.  The data must be exactly
   the same bytes that were supplied when generating the signature.
   This returns true if the signature is a valid signature generated
   by this key for the given data.  Otherways the function returns
   false. False is returned too, if some error is encountered (for
   example, if the key is uncapable of decrypting the data because of
   too short a key). In essence, this means that the signature is
   not valid. */

DLLEXPORT Boolean DLLCALLCONV
ssh_public_key_verify_signature(SshPublicKey key,
                                const unsigned char *signature,
                                size_t signature_len,
                                const unsigned char *data,
                                size_t data_len);

/* As above but with this interface one can give the exact digest one self.
   Idea is that now the data can be gathered in pieces rather than in
   one big block. Following function is available for deriving the
   hash function. */

DLLEXPORT Boolean DLLCALLCONV
ssh_public_key_verify_signature_with_digest(SshPublicKey key,
                                            const unsigned char *signature,
                                            size_t signature_len,
                                            const unsigned char *digest,
                                            size_t digest_len);

/* The hash function used for signature verification computation. Note that
   this hash returned is compatible with the interface for generic
   hash functions. However, there is no need that this particular hash
   function is of some known type. */

DLLEXPORT SshHash DLLCALLCONV
ssh_public_key_derive_signature_hash(SshPublicKey key);

/* A way to change scheme choice on an existing key. For one key type
   there can exists multiple algorithms of same type (e.g. many
   signature algorithms exist for discrete logarithm based methods).
   By using the vararg list where SshPkFormat is used to identify the
   following elements we can select any possible scheme. Returns
   SSH_CRYPTO_OK if everything went fine. Care should be taken to
   see that the SSH_PKF_END tag is at the end of the vararg list. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_select_scheme(SshPublicKey key, ...);

/* Similar to the previous function. This function allows reading of
   exact details of the underlying public key. Using the vararg list
   and the define SshPkFormat type. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_public_key_get_info(SshPublicKey key, ...);

/* Returns the public key group associated with this key, if any. */
DLLEXPORT SshPkGroup DLLCALLCONV
ssh_public_key_derive_pk_group(SshPublicKey key);

/* Private key interfaces. */

/* Constructs a private key object from its binary representation.
   The data will be decrypted by the passphrase. The function returns
   SSH_CRYPTO_OK, if everything went fine. Then *key will contain the
   imported private key. Otherways key might contain garbage. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_import(const unsigned char *buf,
                       size_t len,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,
                       SshPrivateKey *key);

/* As above, but instead of giving the explicit cipher_key one gives a
   passphrase. The passphrase is hashed by crypto library before use. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_import_with_passphrase(const unsigned char *buf,
                                       size_t len,
                                       const char *passphrase,
                                       SshPrivateKey *key);

/* Constructs a key blob (binary representation) for a given private
   key. The sensitive parts of the blob will be encrypted. If
   everything went fine, the function returns SSH_CRYPTO_OK. Then
   *bufptr will point to the blob. Otherways *bufptr might point to
   anywhere. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_export(SshPrivateKey key,
                       const char *cipher_name,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,
                       SshRandomState state,
                       unsigned char **bufptr,
                       size_t *length_return);

/* As above, but instead of giving the explicit cipher_key one gives a
   passphrase. The passphrase is hashed by crypto library before use. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_export_with_passphrase(SshPrivateKey key,
                                       const char *cipher_name,
                                       const char *passphrase,
                                       SshRandomState state,
                                       unsigned char **bufptr,
                                       size_t *length_return);

/* XXX other methods of obtaining a private key: attach to smartcard reader,
   attach to a forwarded agent connection. */

/* Copy private key 'key_src' to 'key_dest'. Explicit copying. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_copy(SshPrivateKey key_src,
                     SshPrivateKey *key_dest);

/* Clears and frees the private key from memory. */

DLLEXPORT void DLLCALLCONV ssh_private_key_free(SshPrivateKey key);

/* Returns the public key corresponding to the private key.  This
   function may also return NULL if the public key cannot be derived
   (e.g., if the private key derives on a smartcard, and no matching
   certificate is available on the card). */

DLLEXPORT SshPublicKey DLLCALLCONV
ssh_private_key_derive_public_key(SshPrivateKey key);

/* This function allows same operation on private key as
   ssh_public_key_select_scheme() on public key. That is, it allows
   one to select an another method for doing private key operations without
   generating a new key. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_select_scheme(SshPrivateKey key, ...);

/* Get detailed information about the private key using SshPkFormat
   style vararg lists. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_get_info(SshPrivateKey key, ...);

/* Returns the group that is used with this key. If not supported returns
   NULL. */
DLLEXPORT SshPkGroup DLLCALLCONV
ssh_private_key_derive_pk_group(SshPrivateKey key);




/* Generate a public key cryptosystems private key. Basic usage is to
   generate a random key of some selected type. Other uses is to give
   explicit key values to be used through SSH interface.

   Vararg list must be handled with care. Returns SSH_CRYPTO_OK if
   everything went fine. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_generate(SshRandomState random_state,
                         SshPrivateKey *key,
                         const char *key_type, ...);

/* Returns the maximum number of bytes that can be signed using this key.
   If this key is not capable of signing, this returns 0. It returns
   (size_t)-1 if signature scheme does its own hashing (i.e.
   any length of input can be given). */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_signature_input_len(SshPrivateKey key);

/* Returns the maximum number size of a signature generated by this key
   (in bytes).  If this key is not capable of signing, this returns 0. */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_signature_output_len(SshPrivateKey key);

/* Returns the maximum number of bytes that can be decrypted using this key.
   If this key is not capable of decryption, this returns 0. */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_decrypt_input_len(SshPrivateKey key);

/* Returns the size of the output buffer required for decrypting data with
   this key. If the key is not capable of decryption, this returns 0. */

DLLEXPORT size_t DLLCALLCONV
ssh_private_key_max_decrypt_output_len(SshPrivateKey key);

/* Decrypts data encrypted with the corresponding public key.  The caller
   must allocate a large enough buffer to contain the decrypted result.
   This will strip any algorithm/encoding-specific padding from the
   encrypted data.

   The plaintext_buffer_len argument is only used to verify that the
   buffer really is large enough.
   
   The function returns SSH_CRYPTO_OK, if everything went fine. Then
   *plaintext_length_return will contain the number of actual
   plaintext in the beginning of *plaintext_buffer. Otherways
   plaintext_buffer and *plaintext_length_return might contain
   garbage. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_decrypt(SshPrivateKey key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        unsigned char *plaintext_buffer,
                        size_t plaintext_buffer_len,
                        size_t *plaintext_length_return);

/* Signs the given data using the private key.  The data will be padded
   and encoded depending on the type of the key before signing.  To verify
   the signature, the same data must be supplied to the verification function
   (along with the corresponding public key).

   The signature_buffer_len argument is only used to verify that the
   buffer really is large enough.

   Most supported methods do their own hashing and formatting.
   
   The function returns SSH_CRYPTO_OK, if everything went fine. Then
   *signature_length_return will contain the length of the actual
   signature, which resides in the beginning of
   signature_buffer. Otherways signature_buffer and
   *signature_length_return might contain garbage. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_sign(SshPrivateKey key,
                     const unsigned char *data,
                     size_t data_len,
                     unsigned char *signature_buffer,
                     size_t signature_buffer_len,
                     size_t *signature_length_return,
                     SshRandomState state);


                     
 /* As above but here one can give the hash digest one self. The hash which
   to use is given by the following function. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_private_key_sign_digest(SshPrivateKey key,
                            const unsigned char *digest,
                            size_t digest_len,
                            unsigned char *signature_buffer,
                            size_t signature_buffer_len,
                            size_t *signature_length_return,
                            SshRandomState state);

/* With this interface we can derive a hash function to gather the
   signature data for signing. Hash function context returned is
   compatible with the generic hash interface of this library. */
DLLEXPORT SshHash DLLCALLCONV
ssh_private_key_derive_signature_hash(SshPrivateKey key);


/* Public key group. */

/* Function to generate public key group. Using the SshPkFormat vararg
   construction. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_generate(SshRandomState state,
                      SshPkGroup *group,
                      const char *group_type, ...);

/* Free public key group context. */
DLLEXPORT void DLLCALLCONV
ssh_pk_group_free(SshPkGroup group);

/* Select a scheme for public key group. Basically only possibilitity
   seems to be Diffie-Hellman. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_select_scheme(SshPkGroup group, ...);

/* Get the group parameters out of the public key group. Equivalent to
   what was explained with private and public key variants. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_get_info(SshPkGroup group, ...);

/* Export group information. Groups contain no user specific information
   and can be distributed freely. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_export(SshPkGroup group,
                    unsigned char **buf,
                    size_t *buf_length);

/* Import a binary blob of group information. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_import(unsigned char *buf,
                    size_t buf_length,
                    SshPkGroup *group);


/* Randomizers. */

/* Count the number of randomizers available through this public
   key group. */
DLLEXPORT unsigned int DLLCALLCONV
ssh_pk_group_count_randomizers(SshPkGroup group);

/* Generate randomizer, a value which can be used in speeding up some
   specific algorithms. Not all methods support randomizers, however.
   Using randomizers can give significant speed-ups for secure
   communications protocols. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_generate_randomizer(SshPkGroup group, SshRandomState state);

/* Export randomizers of a group (all of them). Note that this information
   should be kept strictly secret. */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_export_randomizers(SshPkGroup group,
                                unsigned char **buf,
                                size_t *buf_length);

/* Import a binary blob of randomizers. This blob cannot generate a group,
   and thus should be used only when the receiver is actually the same
   group. In some cases, e.g. in UNIX, some process handling mechanisms
   make this neccessary. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_import_randomizers(SshPkGroup group,
                                unsigned char *buf,
                                size_t buf_length);
                     
/* Diffie-Hellman interface. */

/* Number of octets needed for the setup function. Returns 0 if
   Diffie-Hellman is not supported. */
DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_diffie_hellman_setup_max_output_length(SshPkGroup group);

/* Number of octets needed for the agree function. Returns 0 if
   Diffie-Hellman is not supported. */
DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_diffie_hellman_agree_max_output_length(SshPkGroup group);

/* Generate an exchange value with the Diffie-Hellman protocol. The
   generated public exchange value is placed to the user-supplied
   exchange_buffer. Also a secret is generated which should be hold in
   secret until the agree operation. The secret can be freed with
   ssh_xfree() if the agree operation cannot or shall not be
   called.

   Diffie-Hellman can be visualized as a communication between entities
   A and B, as follows:

     A                            B
   setup                         setup
   send exchange --------->
                <----------    send exchange
   agree                          agree

   
   Be aware that Diffie-Hellman is suspectible to man-in-the-middle
   attacks. To gain authenticated connection you should also use digital
   signatures.
   */
DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_diffie_hellman_setup(SshPkGroup group,
                                  void **secret,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  size_t *return_length,
                                  SshRandomState state);

/* Compute a secret value from an exchange value and a secret. Secret will
   be free and deleted (thus no need to free it otherways). This function
   destroys the secret even when an error occurs. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_diffie_hellman_agree(SshPkGroup group,
                                  void *secret,
                                  unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length,
                                  unsigned char *secret_value_buffer,
                                  size_t secret_value_buffer_length,
                                  size_t *return_length);

/* Unified Diffie-Hellman interface. */

/* Setup functions for Unified Diffie-Hellman are same as those for
   plain Diffie-Hellman. */

/* Number of octets needed for the agree function. Returns 0 if
   Unified Diffie-Hellman is not supported. */
DLLEXPORT size_t DLLCALLCONV
ssh_pk_group_unified_diffie_hellman_agree_max_output_length(SshPkGroup group);

/* Generate an exchange value with the Unified Diffie-Hellman protocol. The
   generated public exchange value is placed to the user-supplied
   exchange_buffer. Also a secret is generated which should be hold in
   secret until the agree operation. The secret can be freed with
   ssh_xfree() if the agree operation cannot or shall not be
   called.

   Unified Diffie-Hellman can be visualized as follows:

        A                             B

     find B's public key       find A's public key
    
      setup                         setup
     send exchange
               ----------------->
                                 send exchange
               <----------------
       agree                         agree

   The problem occurs in phase for finding public keys. These key should
   be certified by some one, or otherwise known to be good.

   */

/* Compute a secret value from an exchange value and a secret. Secret will
   be free and deleted (thus no need to free it otherways). This function
   destroys the secret even when an error occurs.

   As with Diffie-Hellman the returned secret_value_buffer contains
   bits known only by participants of the exchange. However, the buffer
   contains lots of redundancy, thus some function should be run over
   it before use as keying material etc.
   */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_pk_group_unified_diffie_hellman_agree(SshPublicKey public_key,
                                          SshPrivateKey private_key,
                                          void *secret,
                                          unsigned char *exchange_buffer,
                                          size_t exchange_buffer_length,
                                          unsigned char *secret_value_buffer,
                                          size_t secret_value_buffer_length,
                                          size_t *return_length);



#endif /* SSHCRYPT_H */
