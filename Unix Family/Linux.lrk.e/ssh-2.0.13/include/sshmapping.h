/*

sshmapping.h

Author: Toni Tammisalo <ttammisa@acr.fi>
        Mika Kojo <mkojo@ssh.fi>
        
Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved.

Provides functions for efficient storage and retrieval of arbitrary
data objects based on arbitrary keys. The sets are actually implemented
as a hash table.

Functions in this module are NOT re-entrant.  The caller must ensure that
no two operations are concurrently in progress for the same mapping object.
*/

#ifndef MAPPING_H
#define MAPPING_H


/* Type representing the mapping object. */
typedef struct SshMappingRec *SshMapping;

/* Flags for different types of mappings.  These are used by
   ssh_mapping_allocate_with_func. */
typedef unsigned short SshMappingFlags;
/* All keys are typed to unsigned long. Standard interface is used by
   giving pointers to unsigned long variables as arguments.
   XXX Possibly an additional interface might be helpful. */
#define SSH_MAPPING_FL_INTEGER_KEY        1

/* Keys and values are stored as pointers so no additional allocation
   and copying is done. It is callers responsibility to guarantee that
   no such block is freed (or altered accidently) when it is in the
   mapping. If this flag is used, it is also possible to give a
   destructor callback that is used in ssh_mapping_clear and
   ssh_mapping_free. All return parameters are supposed to be pointers
   to pointers. Can be combined with SSH_MAPPING_FL_INTEGER_KEY. */
#define SSH_MAPPING_FL_STORE_POINTERS     2

/* Instead of fixed length keys and values it is possible to allocate
   mappings for variable length objects also. In this case a different
   interface must be used. All functions that pass keys and values
   have alternate version with name ending in '_vl'.  All other
   functions are the same. Normally all values are returned as
   pointers to mappings internal buffers so that in case of remove
   operation that buffer must be freed by the caller with
   ssh_xfree. Instead if return value pointer is ommited the value is
   cached into mapping context. Last such value can be copied with
   ssh_mapping_copy_value_vl which takes a pointer to correct sized
   buffer as a parameter. Can be combined with other flags. */
#define SSH_MAPPING_FL_VARIABLE_LENGTH    4

/* Hash function. Takes void pointer to the key and it's length.
   Returns unsigned long typed hash value. */
typedef unsigned long (*SshMapHashFunctionProc)(const void *key,
                                                size_t key_length);

/* Hash comparing function. Compares two keys of same size (keys
   with differing sizes are assumed to be always different) and
   returns 0 if they are to be considered the same and some other
   integer otherwise. */
typedef int (*SshMapHashCompareProc)(const void *key1,
                                     const void *key2,
                                     size_t key_length);

/* Destructor procedure for both key and value.  If the mapping uses
   integer keys the key pointer must be ignored in destructor. */
typedef void (*SshMapHashDestructorProc)(void *key,
                                         size_t key_length,
                                         void *value,
                                         size_t value_length);

/* This selects one of predefined hash and compare function. */
typedef enum
{
  /* Normal fixed length mapping. */
  SSH_MAPPING_TYPE_FIXED,
  
  /* Fixed length with integer keys.  No hash or compare functions
     are used. */
  SSH_MAPPING_TYPE_INTEGER,

  /* Store pointers with integer keys. No hash or compare (or destructor)
     functions are used. */
  SSH_MAPPING_TYPE_INTEGER_POINTER,
  
  /* Variable length mapping. */
  SSH_MAPPING_TYPE_VARIABLE,

  /* SSH_MAPPING_FL_STORE_POINTERS mapping that uses default hash and
     compare function. No destructor is defined so user is responsible
     for correct removal of all stored pointers even when
     ssh_mapping_free or ssh_mapping_clear is called. */     
  SSH_MAPPING_TYPE_POINTER,

  /* Same as above but with variable length mapping. */
  SSH_MAPPING_TYPE_POINTER_VL,

  /* Same as above but uses CRC-32 as a hash function. */
  SSH_MAPPING_TYPE_POINTER_VL_CRC,
  
  /* (internal) This value ends the internal mapping type array.
     Do not use. */
  SSH_MAPPING_TYPE_END_OF_ARRAY 
} SshMappingType;


/* Allocates the mapping.  The `mapping_type' is used to select on of
   the predefined mapping types. The arguments specify the size (in
   bytes) of both the key and value associated with it. This function
   returns pointer to allocated SshMapping set or NULL in case of
   error. */
SshMapping ssh_mapping_allocate(SshMappingType mapping_type,
                                size_t key_length, size_t value_length);

/* Alternate interface to mapping_allocate that doesn't take
   predefined mapping type. Instead it needs three function pointers,
   one for hash function, one for compare and last one for the
   destructor function (only if SSH_MAPPING_FL_STORE_POINTERS is
   defined). Returns pointer to allocated SshMapping set or NULL if an
   error occured. Can be used to allocate mappings with both fixed and
   variable length keys and values.  If SSH_MAPPING_FL_VARIABLE_LENGTH
   is defined `key_length' and `value_length' are ignored. */
SshMapping ssh_mapping_allocate_with_func(SshMappingFlags flags,
                                          SshMapHashFunctionProc hash_func,
                                          SshMapHashCompareProc compare_func,
                                          SshMapHashDestructorProc destr_func,
                                          size_t key_length,
                                          size_t value_length);
                                   
/* Frees the memory allocated for the set.  Usable for both variable
   and fixed length mappings. */
void ssh_mapping_free(SshMapping set);

/* Removes all mappings from the set, making it empty. Usable for all
   types of mappings. */
void ssh_mapping_clear(SshMapping set);

/* Adds a mapping for a key. Duplicate keys are stored only once.  If
   mapping for this key already exists, the old value is replaced with
   the new one. In that case this returns TRUE, otherwise FALSE.  If
   mapping is allocated with SSH_MAPPING_FL_INTEGER_KEY defined, key
   must be a pointer to unsigned long variable.  Usable only for fixed
   length mappings, variable length mappings must be used through
   ssh_mapping_put_vl. */
Boolean ssh_mapping_put(SshMapping set, void *key, void *value);

/* Removes a mapping for a key. If there was no mapping for specified
   key, FALSE is returned. If mapping existed, this returns TRUE and
   if `value_return' is not NULL, also copies the old mapped value to
   it.  If mapping is allocated with SSH_MAPPING_FL_INTEGER_KEY
   defined, `key' must be a pointer to unsigned long variable.  If
   SSH_MAPPING_FL_STORE_POINTERS is defined `value_return' must be a
   pointer to a pointer of some kind. Usable only for fixed length
   mappings, variable length mappings must be used through
   ssh_mapping_remove_vl. */
Boolean ssh_mapping_remove(SshMapping set, const void *key,
                           void *value_return);

/* Same as ssh_mapping_remove, but if the mapping is STORE_POINTERS
   type, this function also returns the original key pointer in
   'key_return'.  Otherwise it is set to NULL. */
Boolean ssh_mapping_remove_key(SshMapping set, const void *key,
                               void *value_return, void *key_return);

/* Checks the existance of key in set and returns TRUE if it is found,
   FALSE otherwise.  If `value_return' is not NULL, copies also the
   mapped value to buffer pointer in it. If mapping is allocated with
   SSH_MAPPING_FL_INTEGER_KEY defined, `key' must be a pointer to
   unsigned long variable.  If SSH_MAPPING_FL_STORE_POINTERS is
   defined `value_return' must be a pointer to a pointer of some
   kind. Usable only for fixed length mappings, variable length
   mappings must be used through ssh_mapping_get_vl. */
Boolean ssh_mapping_get(const SshMapping set, const void *key,
                        void *value_return);

/* Variable length version of ssh_mapping_put. In addition to
   key and value pointers this also needs their sizes.  Allocates
   space in the mapping and copies the data. If mapping is allocated with
   SSH_MAPPING_FL_INTEGER_KEY defined, `key' must be a pointer to
   unsigned long variable. If SSH_MAPPING_FL_STORE_POINTERS is
   defined no memory is allocated and no copying is done. Instead
   only pointers are stored in mapping. */
Boolean ssh_mapping_put_vl(SshMapping set,
                           void *key, size_t key_length,
                           void *value, size_t value_length);

/* Variable length version of ssh_mapping_remove.  This returns value
   pointer from the mapping and it is callers responsibility to free
   it with ssh_xfree. Values size is returned in `value_length'.  Alternate
   way to use this is give NULL in `value_return'. Then the pointer
   won't be returned but it is cached into mapping context. This
   cached value can then be retrieved with ssh_mapping_copy_value_vl()
   before any other mapping operation overwrites it. Memory allocated
   for this value is automatically freed when invalidated. If mapping
   is allocated with SSH_MAPPING_FL_INTEGER_KEY defined, `key' must be a
   pointer to unsigned long variable. If SSH_MAPPING_FL_STORE_POINTERS
   is defined in mapping no pointers are freed in any case. */
Boolean ssh_mapping_remove_vl(SshMapping set, 
                              const void *key, size_t key_length,
                              void **value_return, size_t *value_length);

/* Same as ssh_mapping_remove_vl, but if the mapping is
   STORE_POINTERS type, this function also returns the original key
   pointer in 'key_return' (and it's size in 'key_length_return'). 
   Otherwise they are set to NULL and zero, respectively. */  
Boolean ssh_mapping_remove_key_vl(SshMapping set, 
                                  const void *key, size_t key_length,
                                  void **value_return, size_t *value_length,
                                  void **key_return, 
                                  size_t *key_length_return);

/* Variable length version of ssh_mapping_get.  Returns a pointer to
   mappings internal buffer so it can't be used if this key is removed
   from mapping or mapping is freed.  Alternate way to use this is
   give NULL in value_return. Then pointer won't be returned but be
   cached into mapping context. This cached value can then be copied
   with ssh_mapping_copy_value_vl() before any other mapping operation
   overwrites it.  If mapping is allocated with
   SSH_MAPPING_FL_INTEGER_KEY, `key' must be a pointer to unsigned
   long variable. */
Boolean ssh_mapping_get_vl(const SshMapping set,
                           const void *key, size_t key_length,
                           void **value_return, size_t *value_length);

/* If ssh_mapping_get_vl or ssh_mapping_remove_vl was called with NULL
   value_return, the otherwise returned value is stored in the
   mapping. This function can be used to copy the value to a given
   buffer. If no value is cached in mapping context or if buffers size
   is wrong (given in `value_return'), this returns FALSE.  Otherwise
   TRUE.  If value was removed from mapping, it is no also freed. If
   SSH_MAPPING_FL_STORE_POINTERS is defined no freeing is done. */
Boolean ssh_mapping_copy_value_vl(SshMapping set,
                                  void *value_return, size_t value_length);

/* Returns the number of mappings in the set. */
unsigned int ssh_mapping_count(const SshMapping set);

/* Returns the size of the hash table underlying the set; this can be
   seen as an overestimate of the number of keys in the set. */
unsigned int ssh_mapping_size(const SshMapping set);

/* These two functions provide a way to loop through the entire
   mapping, one key (and associated value) at time. At first the
   ssh_mapping_reset_index should be called to reset the internal
   index in mapping. After that the repeated calls to
   ssh_mapping_get_next return all the existing mappings from the
   set. When all mappings are processed mapping_get_next will return
   FALSE, otherwise TRUE. If SSH_MAPPING_FL_STORE_POINTERS is defined
   `key_return' and `value_return' must be pointers to some type of
   pointers. If SSH_MAPPING_FL_INTEGER_KEY is defined `key_return'
   must be a pointer to unsigned long variable.

   It must be noted that no operations that can possibly change
   the size of the mapping (put and remove) can be made during
   this procedure.  */
void ssh_mapping_reset_index(SshMapping set);

Boolean ssh_mapping_get_next(SshMapping set, void *key_return,
                             void *value_return);


/* Variable length version of ssh_mapping_get_next. Returns pointers
   to mappings internal buffers for both key (except for integer keys,
   which are copied normally) and value and their sizes. */

Boolean ssh_mapping_get_next_vl(SshMapping set,
                                void **key_return, size_t *key_length,
                                void **value_return, size_t *value_length);

/* Refresh lock allows/disallows refreshes when removing entries. */

/* Set refresh lock. Changes the refresh lock to the given flag value.
   Function returns the previous flag value. */
Boolean ssh_mapping_set_refresh_lock(SshMapping set, Boolean flag);

/* Default hash function */
unsigned long ssh_default_hash_function(const void *key,
                                        size_t key_length);

/* Default compare function, uses memcmp */
int ssh_default_compare_function(const void *key1,
                                 const void *key2,
                                 size_t key_length);

/* Default destructor function, uses ssh_xfree */
void ssh_default_destructor_function(void *key,
                                     size_t key_length,
                                     void *value,
                                     size_t value_length);

#endif /* MAPPING_H */
