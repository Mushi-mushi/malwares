/*

mapping.c

Author: Toni Tammisalo <ttammisalo@acr.fi>
        Mika Kojo <mkojo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved.

Provides functions for efficient storage and retrieval of arbitrary
data object based on arbitrary keys. The sets are actually implemented
as a hash table.

This code is based on the "mapping" implementation written by Kenneth
Oksanen for the Shadows project at Helsinki University of Technology
in 1993-1994.
*/

#include "sshincludes.h"
#include "sshcrc32.h"
#include "sshmapping.h"


#ifdef PRIME_TABLE
#define SSH_MAPPING_MINIMUM_SIZE_SHIFT 3
#define SSH_MAPPING_MINIMUM_SIZE 11
const unsigned long prime_table[32] = 
{ 
           1,           3,           5,          11,          17,
          37,          67,         131,         257,         521,
        1031,        2053,        4099,        8209,       16411,
       32771,       65537,      131101,      262147,      524309,
     1048583,     2097169,     4194319,     8388617,    16777259,
    33554467,    67108879,   134217757,   268435459,   536870923,
  1073741827,  2147483659
};
#else
#define SSH_MAPPING_MINIMUM_SIZE 8
#endif /* PRIME_TABLE */


/* Internal type for an element of the hash table. Key is defined as
   an union because of integer keys. */
typedef struct SshMappingEntryRec
{
  /* Hash value for this key. '0' means empty and '1' is semi empty. */
  unsigned long h;

  /* Pointer to value of this key. */
  void *value;

  /* Actual key is stored in union. If integer keys are used, they are
     stored directly in key.i. Otherwise key.p points to a buffer
     allocated for it (if SSH_MAPPING_FL_STORE_POINTERS is used, this is
     an external buffer). */
  union {
    void *p;
    unsigned long i;
  } key;
} SshMappingEntry;

/* Internal type for an element of the hash table with variable length
   keys and values. Key is defined as an union because of integer keys. */
typedef struct SshMappingEntryVLRec
{
  /* Hash value for this key. '0' means empty and '1' is semi empty. */
  unsigned long h;

  /* Lengths of both the key and the associated value. */
  size_t key_length;
  size_t value_length;

  /* Pointer to buffer allocated for value. This pointer is returned
     directly in ssh_mapping_get_vl() and ssh_mapping_remove_vl(). */
  void *value;

  /* Either integer key directly or pointer to a variable length key
     that is freed automaticly in ssh_mapping_remove_vl() and return
     in ssh_mapping_get_next_vl(). */     
  union {
    void *p;
    unsigned long i;
  } key;
} SshMappingEntryVL;


/* Structure defining the mapping type. Includes pointers to hash function,
   compare function and destructor. */   
typedef struct SshMappingTypeEntryRec
{
  SshMappingType type;
  SshMappingFlags flags;
  SshMapHashFunctionProc hash_function;
  SshMapHashCompareProc compare;
  SshMapHashDestructorProc destructor;
} SshMappingTypeEntry;


/* Type representing the mapping object.  The contents of this type are
   private, and the fields should not be accessed directly. */
struct SshMappingRec
{
  /* Flags defining the type of mapping this context represents. */
  unsigned short flags;

  /* This is a lock flag for refresh. */
  Boolean refresh_lock;
  
  /* Mappings size, number of totally empty cells and number of
     semi empties (cells that are removed). */
  unsigned long size;
  unsigned long empties;
  unsigned long semi_empties;

#ifdef PRIME_TABLE
  unsigned long size_shift;
#endif
  
  /* Pointer to hash function. In case of integer keys it is not
     necessary (but can still be used if wanted). */
  SshMapHashFunctionProc hash_function;
  /* Compare function. Compares two keys. */
  SshMapHashCompareProc compare_function;
  /* Destructor function. Only used if SSH_MAPPING_FL_STORE_POINTER
     is given. Called in ssh_mapping_free_hashtable(). */
  SshMapHashDestructorProc destructor_function;

  /* Size of the key and the value. Ignored with variable length
     values. */
  size_t key_length;
  size_t value_length;

  /* Index used in ssh_mapping_get_next.  Allows linear searching
     through the mapping. */
  unsigned long idx;

  /* All fields before this are assumed to be constant in all
     different internal context types. */
  
  /* Pointer to the hash table. */
  SshMappingEntry *t;
};

/* Type representing the mapping object supporting variable length
   keys and stored values. */
typedef struct SshMappingVLRec
{
  /* Flags defining the type of mapping this context represents. */
  unsigned short flags;

  /* This is a lock flag for refresh. */
  Boolean refresh_lock;

  /* Mappings size, number of totally empty cells and number of
     semi empties (cells that are removed). */
  unsigned long size;
  unsigned long empties;
  unsigned long semi_empties;

#ifdef PRIME_TABLE
  unsigned long size_shift;
#endif
  
  /* Pointers to hash, compare and destructor functions. */
  SshMapHashFunctionProc hash_function;
  SshMapHashCompareProc compare_function;
  SshMapHashDestructorProc destructor_function;

  /* Default sizes for keys and values. At the moment this is
     ignored with variable length mappings. */
  size_t key_length;
  size_t value_length;

  /* Index used in ssh_mapping_get_next.  Allows linear searching
     through the mapping. */
  unsigned long idx;

  /* All fields before this are assumed to be constant in all
     different internal context types. */
  
  /* Pointer to the hash table. */
  SshMappingEntryVL *t;

  /* Pointer to a cache value. */
  void *cached_value;

  /* Length of the cached value. */  
  size_t cached_length;

  /* Is this value to be freed after invalidated? */
  Boolean remove_value;
  
} *SshMappingVL;


/* Calculates a hash value from a buffer. */

unsigned long ssh_default_hash_function(const void *key,
                                        size_t key_length)
{
  size_t i;
  unsigned long hash;
  
  for (i = 0, hash = 0xabcdef01; i < key_length; i++)
    {
      hash = (hash << 1) | (hash >> 31);
      hash += (unsigned long)((unsigned char *)key)[i];
    }

  return hash;
}

unsigned long ssh_default_hash_crc_function(const void *key,
                                            size_t key_length)
{
  return crc32_buffer((const unsigned char *)key,
                      (key_length & 0xffffffff));
}

/* Default compare function, uses memcmp directly. */

int ssh_default_compare_function(const void *key1,
                                 const void *key2,
                                 size_t key_length)
{
  return memcmp(key1, key2, key_length);
}

/* Default destructor function, uses ssh_xfree */
void ssh_default_destructor_function(void *key,
                                     size_t key_length,
                                     void *value,
                                     size_t value_length)
{
  ssh_xfree(key);
  ssh_xfree(value);
}


/* Array of predefined mapping types. This array is searched
   in ssh_mapping_allocated with the given SshMappingType. */

SshMappingTypeEntry ssh_mapping_type_array[] = 
{
  { SSH_MAPPING_TYPE_FIXED,
    0,
    ssh_default_hash_function,
    ssh_default_compare_function,
    NULL },

  { SSH_MAPPING_TYPE_INTEGER,
    SSH_MAPPING_FL_INTEGER_KEY,
    NULL,
    NULL,
    NULL },

  { SSH_MAPPING_TYPE_INTEGER_POINTER,
    SSH_MAPPING_FL_INTEGER_KEY | SSH_MAPPING_FL_STORE_POINTERS,
    NULL,
    NULL,
    NULL },
  
  { SSH_MAPPING_TYPE_VARIABLE,
    SSH_MAPPING_FL_VARIABLE_LENGTH,
    ssh_default_hash_function,
    ssh_default_compare_function,
    NULL },

  { SSH_MAPPING_TYPE_POINTER,
    SSH_MAPPING_FL_STORE_POINTERS,
    ssh_default_hash_function,
    ssh_default_compare_function,
    NULL },

  { SSH_MAPPING_TYPE_POINTER_VL,
    SSH_MAPPING_FL_STORE_POINTERS | SSH_MAPPING_FL_VARIABLE_LENGTH,
    ssh_default_hash_function,
    ssh_default_compare_function,
    NULL },

  { SSH_MAPPING_TYPE_POINTER_VL_CRC,
    SSH_MAPPING_FL_STORE_POINTERS | SSH_MAPPING_FL_VARIABLE_LENGTH,
    ssh_default_hash_crc_function,
    ssh_default_compare_function,
    NULL },
  
  /* This should be allways the last item. */
  { SSH_MAPPING_TYPE_END_OF_ARRAY, 0, NULL, NULL, NULL }
};


/* This is called in case of unrecoverable error. Replace
   with something else if needed. */

void ssh_mapping_fatal(void)
{
  ssh_fatal("fatal error in mapping.");
}


#ifdef PRIME_TABLE                            
#define REDUCE_HASH(size, h, h1, h2)         \
  (h1) = (h) % (size);                       \
  (h2) = (((h) % (size >> 1))) | 0x1;                             
#else
#define REDUCE_HASH(size, h, h1, h2)         \
  (h1) = (h) & ((size) - 1);                 \
  (h2) = (((h) >> 2) | 0x1) & 0xFF;          
#endif /* PRIME_TABLE */ 

#ifdef PRIME_TABLE                                     
#define MODULO_ADD(size, h1, h2)             \
  (h1) += (h2);                              \
  if ((h1) >= (size))                        \
    (h1) = (h1) - (size);                          
#else
#define MODULO_ADD(size, h1, h2)             \
  (h1) = ((h1) + (h2)) & ((size) - 1);       
#endif /* PRIME_TABLE */
        

/* Allocate space for the hash table. The size is given as argument. */

SshMappingEntry *ssh_mapping_allocate_hashtable(SshMapping set,
                                                unsigned int size)
{
  SshMappingEntry *t = NULL;
  
  /* Allocate a hash table. */
  t = (SshMappingEntry *) ssh_xmalloc(size * sizeof(SshMappingEntry));
  if (t == NULL)
    return NULL;
  /* Clear it. */
  memset(t, 0, size * sizeof(SshMappingEntry));
    
  return t;
}


/* Allocate space for hash table with variable length keys. */

SshMappingEntryVL *ssh_mapping_allocate_hashtable_vl(SshMappingVL set,
                                                     unsigned int size)
{
  SshMappingEntryVL *t = NULL;
  
  /* Allocate a hash table. */
  t = (SshMappingEntryVL *) ssh_xmalloc(size * sizeof(SshMappingEntryVL));
  if (t == NULL)
    return NULL;
  /* Clear it. */
  memset(t, 0, size * sizeof(SshMappingEntryVL));
    
  return t;
}


/* Frees just the sets allocated hash table. */

void ssh_mapping_free_hashtable(SshMapping set)
{
  int i;

  /* Loop through the hash array. */
  for (i = 0; i < set->size; i++)
    {
      if (set->t[i].h > 1)
        {
          /* If the cell is not empty or semi empty, call the
             destructor for the key and the value. If no destructor is
             defined, just free the value. This also frees the memory
             possibly allocated for key. */
          if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
            {
              if (set->destructor_function)
                set->destructor_function(set->t[i].key.p, set->key_length,
                                         set->t[i].value, set->value_length);
            }
          else
            ssh_xfree(set->t[i].value);
        }
    }
  ssh_xfree(set->t);
}


/* Frees variable length hash table. */

void ssh_mapping_free_hashtable_vl(SshMappingVL set)
{
  int i;
  
  /* Loop through the hash array. */
  for (i = 0; i < set->size; i++)
    {
      if (set->t[i].h > 1)
        {
          if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
            {
              if (set->destructor_function)
                set->destructor_function(set->t[i].key.p, set->key_length,
                                         set->t[i].value, set->value_length);
            }
          else
            {
              /* Possible key and value must be deallocated separately. */
              if (!(set->flags & SSH_MAPPING_FL_INTEGER_KEY))
                ssh_xfree(set->t[i].key.p);
              ssh_xfree(set->t[i].value);
            }
        }
    }
  ssh_xfree(set->t);
}


/* Allocates a mapping set for variable length keys and
   values. */

SshMapping ssh_mapping_allocate_vl(SshMappingFlags flags,
                                   SshMapHashFunctionProc hash_func,
                                   SshMapHashCompareProc compare_func,
                                   size_t key_length,
                                   size_t value_length)
{
  SshMappingVL set;

  set = ssh_xmalloc(sizeof(*set));

  /* Initialize all variables. */
  set->flags = flags;
  set->refresh_lock = FALSE;

#ifdef PRIME_TABLE
  set->size_shift = SSH_MAPPING_MINIMUM_SIZE_SHIFT;    
  set->empties = set->size = prime_table[set->size_shift];
#else    
  set->empties = set->size = SSH_MAPPING_MINIMUM_SIZE;
#endif /* PRIME_TABLE */
  
  set->semi_empties = 0;

  /* These aren't actually used. XXX Atleast not now. */
  set->key_length = key_length;
  set->value_length = value_length;

  /* Key length for integer keys is 0. */
  if (flags & SSH_MAPPING_FL_INTEGER_KEY)
    set->key_length = 0;

  /* Set the function pointers. */
  set->hash_function = hash_func;
  set->compare_function = compare_func;
  set->destructor_function = NULL;

  /* Allocates a hash table of correct size. */
  set->t = ssh_mapping_allocate_hashtable_vl(set, set->size);  

  /* Initialize the index. */
  set->idx = 0;

  /* Initialize value cache. */
  set->cached_value = NULL;
  set->cached_length = 0;
  set->remove_value = FALSE;
  
  /* Return the allocated set. */
  return (SshMapping) set;
}


/* Alternate interface to mapping_allocate that doesn't take
   predefined hash type. Instead it need two function pointers,
   one for hash function and other for compare. Returns pointer to
   allocated SshMapping set or NULL if an error occured. */
SshMapping ssh_mapping_allocate_with_func(SshMappingFlags flags,
                                          SshMapHashFunctionProc hash_func,
                                          SshMapHashCompareProc compare_func,
                                          SshMapHashDestructorProc destr_func,
                                          size_t key_length,
                                          size_t value_length)
{
  SshMapping set;

  /* If a variable length mapping is requested, allocate it with
     ssh_mapping_allocate_vl and just return the result. */
  if (flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    {
      set = ssh_mapping_allocate_vl(flags, hash_func, compare_func,
                                    key_length, value_length);
      return set;
    }

  set = ssh_xmalloc(sizeof(*set));

  /* Initialize all variables. */
  set->flags = flags;
  set->refresh_lock = FALSE;

#ifdef PRIME_TABLE
  set->size_shift = SSH_MAPPING_MINIMUM_SIZE_SHIFT;    
  set->empties = set->size = prime_table[set->size_shift];
#else    
  set->empties = set->size = SSH_MAPPING_MINIMUM_SIZE;
#endif /* PRIME_TABLE */

  set->semi_empties = 0;

  set->key_length = key_length;
  set->value_length = value_length;

  /* Key length for integer keys is set to zero so that size calculation
     in ssh_mapping_put() would work correctly. */
  if (flags & SSH_MAPPING_FL_INTEGER_KEY)
    set->key_length = 0;

  /* Set all function pointers. */
  set->hash_function = hash_func;
  set->compare_function = compare_func;
  /* Destructor is should be only used if SSH_MAPPING_FL_STORE_POINTERS
     is defined. */
  if (flags & SSH_MAPPING_FL_STORE_POINTERS)
    set->destructor_function = destr_func;
  else
    set->destructor_function = NULL;

  /* Allocates a hash table of correct size. */
  set->t = ssh_mapping_allocate_hashtable(set, set->size);  

  /* Initialize the index variable. */
  set->idx = 0;
  
  return set;
}


/* Allocates the mapping.  The arguments specify the size (in bytes)
   of both the key and value associated with it. This function returns
   pointer to allocated SshMapping set or NULL in case of error. */
SshMapping ssh_mapping_allocate(SshMappingType mapping_type,
                                size_t key_length, size_t value_length)
{
  SshMapping set;
  int i;
  
  /* Search the array for a correct predefined mapping type. */
  for (i = 0;
       ssh_mapping_type_array[i].type != SSH_MAPPING_TYPE_END_OF_ARRAY;
       i++)
    {
      if (ssh_mapping_type_array[i].type == mapping_type)
        break;
    }
  /* If the requested type was not in array, fail by returing NULL. */
  if (ssh_mapping_type_array[i].type == SSH_MAPPING_TYPE_END_OF_ARRAY)
    return NULL;

  /* Allocate actual set with ssh_mapping_with_func(). */
  set = ssh_mapping_allocate_with_func(ssh_mapping_type_array[i].flags,
                                       ssh_mapping_type_array[i].hash_function,
                                       ssh_mapping_type_array[i].compare,
                                       ssh_mapping_type_array[i].destructor,
                                       key_length, value_length);

  /* Return the allocated set. */
  return set;
}


/* Frees the memory allocated for mapping. */

void ssh_mapping_free(SshMapping set)
{
  SshMappingVL vlset;
  
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    {
      vlset = (SshMappingVL) set;
      
      ssh_mapping_free_hashtable_vl(vlset);

      /* If there is a remove value stores in context, free it here. */
      if (vlset->remove_value &&
          !(vlset->flags & SSH_MAPPING_FL_STORE_POINTERS))
        ssh_xfree(vlset->cached_value);
      
      ssh_xfree(vlset);
      return;
    }
  ssh_mapping_free_hashtable(set);
  ssh_xfree(set);
}


/* Removes all mappings from the set, making it empty. */

void ssh_mapping_clear(SshMapping set)
{
  SshMappingVL vlset;
  
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    {
      vlset = (SshMappingVL) set;
      
      /* First we free the mapping. */     
      ssh_mapping_free_hashtable_vl(vlset);
      
      /* Reinitialize mapping size to the minimum. */
      vlset->semi_empties = 0;
      
#ifdef PRIME_TABLE
      vlset->size_shift = SSH_MAPPING_MINIMUM_SIZE_SHIFT;
      vlset->size = prime_table[vlset->size_shift];
#else
      vlset->size = SSH_MAPPING_MINIMUM_SIZE;
#endif /* PRIME_TABLE */
      
      vlset->empties = vlset->size;

      /* If there is a remove value stores in context, free it here. */
      if (vlset->remove_value &&
          !(vlset->flags & SSH_MAPPING_FL_STORE_POINTERS))
        ssh_xfree(vlset->cached_value);
      vlset->cached_value = NULL;
      
      /* Allocate space for a new mapping. */
      vlset->t = ssh_mapping_allocate_hashtable_vl(vlset, vlset->size);
      return;
    }
      
  /* First we free the mapping. */     
  ssh_mapping_free_hashtable(set);

  /* Reinitialize mapping size to the minimum. */
  set->semi_empties = 0;
  set->size = SSH_MAPPING_MINIMUM_SIZE;
  set->empties = set->size;

  /* Allocate space for a new mapping. */
  set->t = ssh_mapping_allocate_hashtable(set, set->size);
}


/* With lots of varying traffic the hash table may become deteriorated
   with lots of semi empties in `t'. This routine can be used to get
   rid of them all. Simultaneously the hash table size may be adjusted.
   */

void ssh_mapping_refresh(SshMapping set, int new_size)
{
  SshMappingEntry *nt = NULL; 
  unsigned long h, h1, h2;
  int i;

  /* Allocate space for a new array. */
  nt = ssh_mapping_allocate_hashtable(set, new_size);

  /* Inserts all items from old mapping into a new one. */
  for (i = 0; i < set->size; i++)
    if ((unsigned long)set->t[i].h > 1)
      {
        h = set->t[i].h;
        REDUCE_HASH(new_size, h, h1, h2);
        while (nt[h1].h != 0)
          {
            MODULO_ADD(new_size, h1, h2);
          }
        memcpy(&nt[h1], &set->t[i], sizeof(SshMappingEntry));
      }

  /* Free the old array and start using the new one. */
  ssh_xfree(set->t);
  set->t = nt;
  set->empties += set->semi_empties + new_size - set->size;
  set->semi_empties = 0;
  set->size = new_size;
}


/* Copy only pointers to mapping entry. */

static void ssh_mapping_set_entry(SshMapping set, unsigned long i,
                                  void *key, void *value)
{
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    set->t[i].key.i = *((unsigned long *)key);
  else
    set->t[i].key.p = key;
  
  set->t[i].value = value;
}


/* Compares a key to another key stored in hash table with
   index. */   
#define SSH_MAPPING_COMPARE_KEY(set, idx, keyp)           \
(((set)->flags & SSH_MAPPING_FL_INTEGER_KEY) ?              \
 ((set)->t[idx].key.i == *((unsigned long *)keyp)) :      \
 ((set)->compare_function((keyp), (set)->t[(idx)].key.p,  \
                          (set)->key_length) == 0))

/* Adds a mapping for a key. Duplicate pages are stored only once.  If
   mapping for this key already exists, the old value is replaced with
   the new one. In that case this returns TRUE, otherwise FALSE. */
Boolean ssh_mapping_put(SshMapping set, void *key, void *value)
{
  unsigned long h, h1, h2, start;
  unsigned long flag;
  int i = -1, semi_empty_count = 0;

  /* This should not be used with variable length mappings. */
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    ssh_mapping_fatal();
  
  /* Increase set size if already half full. */
  if (set->empties + set->semi_empties <= (set->size >> 1))
    {
#ifdef PRIME_TABLE
      set->size_shift++;
      ssh_mapping_refresh(set, prime_table[set->size_shift]);
#else
      ssh_mapping_refresh(set, 2*set->size);
#endif /* PRIME_TABLE */
    }

  /* Calculate a hash value for the key. */
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        /* In case of integer keys, the key can be used directly. */
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, set->key_length);

  /* Guarantee that hash value is always greater than 1. */
  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);
          
  start = h1;
  
  /* i is the index of the first entry where the mapping can be put if 
     no old mapping with an equal key is found. */
  while (1)
    {
      flag = set->t[h1].h;
      if (flag < 2)
        {
          if (i < 0)
            i = h1;
          if (flag == 0)
            break;
          semi_empty_count++;
        }
      else
        {
          if (flag == h &&
              SSH_MAPPING_COMPARE_KEY(set, h1, key))
            {
              i = h1;
              break;
            }
        }
      MODULO_ADD(set->size, h1, h2);
      if (h1 == start)
        {
          if (i != -1)
            break;
          ssh_mapping_fatal();
        }
    }

  set->t[i].h = h;

  if (flag != h)
    {      
      if (i == (int) h1)
        set->empties--;
      else
        set->semi_empties--;

      /* Allocate a new buffer for key and it's value and copy
         the data. */
      if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
        ssh_mapping_set_entry(set, i, key, value);
      else
        {
          /* Allocate space for value and possibly for the key also. */
          set->t[i].value = ssh_xmalloc(set->key_length + set->value_length);

          /* Copy the value to the buffer. */
          memcpy(set->t[i].value, value, set->value_length);

          /* Copy the key. */
          if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
            set->t[i].key.i = *((unsigned long *)key);
          else
            {
              set->t[i].key.p = (unsigned char *) set->t[i].value +
                set->value_length;
              memcpy(set->t[i].key.p, key, set->key_length);
            }
        }
      return FALSE;
    }

  /* Mapping for this key already existed. Replace the old value with
     a new one. */
  if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
    set->t[i].value = value;
  else
    memcpy(set->t[i].value, value, set->value_length);
  return TRUE;
}


/* Checks the existance of key in set and returns TRUE if it is found,
   FALSE otherwise.  If value_return is not NULL, copies also the mapped
   value to buffer pointer in it. */
Boolean ssh_mapping_get(const SshMapping set, const void *key,
                        void *value_return)
{
  unsigned long h, h1, flag;
  unsigned long h2, start;

  /* This should not be used with variable length mappings. */
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE;  /* Empty set, not a member. */

  /* Calculate a hash value for the key. */
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        /* In case of integer keys, the key can be used directly. */
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, set->key_length);

  /* Guarantee that hash value is always greater than 1. */
  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);

  flag = set->t[h1].h;

  if (flag == h &&
      SSH_MAPPING_COMPARE_KEY(set, h1, key))
    {
      if (value_return)
        {
          if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
            *((void **)value_return) = set->t[h1].value;
          else
            memcpy(value_return, set->t[h1].value, set->value_length);
        }
      return TRUE;
    }
  else
    {
      if (flag == 0)
        return FALSE;
    }

  start = h1;
  
  while (1)
    {
      MODULO_ADD(set->size, h1, h2);
      flag = set->t[h1].h;
      if (flag == h &&
          SSH_MAPPING_COMPARE_KEY(set, h1, key))
        {
          if (value_return)
            {
              if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
                *((void **)value_return) = set->t[h1].value;
              else
                memcpy(value_return, set->t[h1].value, set->value_length);
            }
          return TRUE;
        }
      else if (flag == 0)
        return FALSE;
      if (h1 == start)
        return FALSE;     
    }  
}


/* Removes mapping for a key. If there was no mapping for specified
   key, FALSE is returned. If mapping existed, this returns TRUE and
   if value_return is not NULL, also copies the old mapped value to
   it. */
Boolean ssh_mapping_remove(SshMapping set, const void *key,
                           void *value_return)
{
  return ssh_mapping_remove_key(set, key, value_return, NULL);
}


/* Same as ssh_mapping_remove, but if the mapping is STORE_POINTERS
   type, this function also returns the original key pointer in
   'key_return'.  Otherwise it is set to NULL. */
Boolean ssh_mapping_remove_key(SshMapping set, const void *key,
                               void *value_return, void *key_return)
{
  unsigned long h, h1, h2;
  unsigned long flag, start;
  
  if (key_return != NULL)
    *((void **)key_return) = NULL;

  /* This should not be used with variable length mappings. */
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE;  /* Empty set, not a member. */
  
  /* Calculate a hash value for the key. */
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        /* In case of integer keys, the key can be used directly. */
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, set->key_length);

  /* Guarantee that hash value is always greater than 1. */
  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);

  start = h1;
  
  while (1)
    {
      flag = set->t[h1].h;
      if (flag == h &&
          SSH_MAPPING_COMPARE_KEY(set, h1, key))
        break;
      else if (flag == 0)
        return FALSE;
      MODULO_ADD(set->size, h1, h2);
      if (start == h1)
        return FALSE;
    }

  set->semi_empties++;
  set->t[h1].h = 1;
  if (value_return)
    {
      if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
        {
          *((void **)value_return) = set->t[h1].value;
          if (key_return != NULL)
            *((void **)key_return) = set->t[h1].key.p;
        }
      else
        {
          memcpy(value_return, set->t[h1].value, set->value_length);
          ssh_xfree(set->t[h1].value);
        }
    }
  
  /* Decrease the size of the hash table if it appears 
     to be mostly empty. */

  /* if (3*set->semi_empties > (set->size >> 3) + set->empties) */
  if (set->refresh_lock == FALSE &&
      set->semi_empties > (set->size >> 3))
    {
      if (set->size > SSH_MAPPING_MINIMUM_SIZE &&
          set->size - set->empties - set->semi_empties < (set->size >> 4))
        {
#ifdef PRIME_TABLE
          set->size_shift--;
          ssh_mapping_refresh(set, prime_table[set->size_shift]);
#else
          ssh_mapping_refresh(set, set->size >> 1);
#endif /* PRIME_TABLE */
        }
      else  
        ssh_mapping_refresh(set, set->size);
    }
  
  return TRUE;
}

/* Returns the number of mappings in the set. */

unsigned int ssh_mapping_count(const SshMapping set)
{
  return set->size - set->empties - set->semi_empties;
}


/* Returns the size of the hash table underlying the set; this can be seen
   as an overestimate of the number of keys in the set. */

unsigned int ssh_mapping_size(const SshMapping set)
{
  return set->size;
}


/* These two functions provide a way to loop through the entire
   mapping, one key (and associated value) at time. At first
   the mapping_reset_index should be called to reset the internal
   index in mapping. After that the repeated calls to mapping_get_next
   return all the existing mappings from the set. When all mappings are
   processed mapping_get_next will return FALSE, otherwise TRUE.

   It must be noted that not operations that can possibly change
   the size of the mapping (put and remove) can be made during
   this procedure.  */
void ssh_mapping_reset_index(SshMapping set)
{
  set->idx = 0;
}

Boolean ssh_mapping_get_next(SshMapping set, void *key_return,
                             void *value_return)
{
  unsigned long i;

  /* This should not be used with variable length mappings. */
  if (set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH)
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE; /* Empty set, nothing more found. */

  for (i = set->idx; i < set->size; i++)
    if (set->t[i].h > 1)
      {
        set->idx = i + 1;
        if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
          {
            if (key_return)
              {
                if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
                  *((unsigned long *)key_return) = set->t[i].key.i;
                else
                  *((void **)key_return) = set->t[i].key.p;
              }
            if (value_return)
              *((void **)value_return) = set->t[i].value;           
            return TRUE;
          }
        
        if (key_return)
          {
            if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
              *((unsigned long *)key_return) = set->t[i].key.i;
            else
              memcpy(key_return, set->t[i].key.p, set->key_length);
          }
        if (value_return)
          memcpy(value_return, set->t[i].value, set->value_length);
        return TRUE;
      }

  return FALSE;
}


/* Alternate interface supporting variable length keys and values. */


/* Refresh function for variable length sets. */

void ssh_mapping_refresh_vl(SshMappingVL set, int new_size)
{
  SshMappingEntryVL *nt = NULL; 
  unsigned long h, h1, h2;
  int i;

  /* Allocate space for a new array. */
  nt = ssh_mapping_allocate_hashtable_vl(set, new_size);

  /* Inserts all items from old mapping into a new one. */
  for (i = 0; i < set->size; i++)
    if ((unsigned long)set->t[i].h > 1)
      {
        h = set->t[i].h;
        REDUCE_HASH(new_size, h, h1, h2); 
        while (nt[h1].h != 0)
          {
            MODULO_ADD(new_size, h1, h2);
          }
        memcpy(&nt[h1], &set->t[i], sizeof(SshMappingEntryVL));
      }

  /* Free the old array and start using the new one. */
  ssh_xfree(set->t);
  set->t = nt;
  set->empties += set->semi_empties + new_size - set->size;
  set->semi_empties = 0;
  set->size = new_size;
}


/* Copy only pointers to mapping entry. */

static void ssh_mapping_set_entry_vl(SshMappingVL set, unsigned long i,
                                     void *key, void *value)
{
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    set->t[i].key.i = *((unsigned long *)key);
  else
    set->t[i].key.p = key;
  
  set->t[i].value = value;
}

/* Compares a key to another key stored in hash table with
   index. */   
#define SSH_MAPPING_COMPARE_KEY_VL(set, idx, keyp, keylen) \
(((set)->flags & SSH_MAPPING_FL_INTEGER_KEY) ? \
 ((set)->t[idx].key.i == *((unsigned long *)(keyp))) : \
 (((set)->t[(idx)].key_length == (keylen)) && \
  ((set)->compare_function((keyp), (set)->t[(idx)].key.p, (keylen)) == 0)))

/* Variable length version of ssh_mapping_put. In addition to
   key and value pointers this also needs their sizes. */
Boolean ssh_mapping_put_vl(SshMapping normal_set,
                           void *key, size_t key_length,
                           void *value, size_t value_length)
{
  SshMappingVL set = (SshMappingVL) normal_set;
  unsigned long h, h1, h2, start;
  unsigned long flag;
  int i = -1, semi_empty_count = 0;

  if (!(set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH))
    ssh_mapping_fatal();
  
  /* Increase set size if already half full. */
  if (set->empties + set->semi_empties <= (set->size >> 1))
    {
#ifdef PRIME_TABLE
      set->size_shift++;
      ssh_mapping_refresh_vl(set, prime_table[set->size_shift]);
#else
      ssh_mapping_refresh_vl(set, set->size << 1);
#endif /* PRIME_TABLE */
    }
  
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, key_length);

  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);

  start = h1;
  
  /* i is the index of the first entry where the mapping can be put if 
     no old mapping with an equal key is found. */
  while (1)
    {
      flag = set->t[h1].h;
      if (flag < 2)
        {
          if (i < 0)
            i = h1;
          if (flag == 0)
            break;
          semi_empty_count++;
        }
      else
        {
          if (flag == h &&
              SSH_MAPPING_COMPARE_KEY_VL(set, h1, key, key_length))
            {
              i = h1;
              break;
            }
        }
      MODULO_ADD(set->size, h1, h2);
      if (h1 == start)
        {
          if (i != -1)
            break;
          ssh_mapping_fatal();
        }
    }

  set->t[i].h = h;

  if (flag != h)
    {      
      if (i == (int) h1)
        set->empties--;
      else
        set->semi_empties--;

      /* Allocate a new buffer for key and it's value and copy
         the data. */
      set->t[i].key_length = key_length;
      set->t[i].value_length = value_length;

      if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
        ssh_mapping_set_entry_vl(set, i, key, value);
      else
        {
          set->t[i].value = ssh_xmalloc(value_length);
          memcpy(set->t[i].value, value, value_length);
          if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
            set->t[i].key.i = *((unsigned long *)key);
          else
            {
              set->t[i].key.p = ssh_xmalloc(key_length);
              memcpy(set->t[i].key.p, key, key_length);
            }
        }
      return FALSE;
    }

  /* Mapping for this key already existed. Replace the old value with
     a new one. */
  if (set->flags & SSH_MAPPING_FL_STORE_POINTERS)
    {
      set->t[i].value_length = value_length;
      ssh_mapping_set_entry_vl(set, i, key, value);
    }
  else
    {
      if (value_length == set->t[i].value_length)
        memcpy(set->t[i].value, value, value_length);
      else
        {
          ssh_xfree(set->t[i].value);
          set->t[i].value_length = value_length;
          set->t[i].value = ssh_xmalloc(value_length);      
          memcpy(set->t[i].value, value, value_length);
        }
    }
  
  return TRUE;
}


/* Variable length version of ssh_mapping_remove. This returns value
   pointer from the mapping and it is callers responsibility to
   free it with ssh_xfree. */
Boolean ssh_mapping_remove_vl(SshMapping normal_set, 
                              const void *key, size_t key_length,
                              void **value_return, size_t *value_length)
{
  return ssh_mapping_remove_key_vl(normal_set, key, key_length, 
                                   value_return, value_length, 
                                   NULL, NULL);
}

/* Same as ssh_mapping_remove_vl, but if the mapping is
   STORE_POINTERS type, this function also returns the original key
   pointer in 'key_return' (and it's size in 'key_length_return'). 
   Otherwise they are set to NULL and zero, respectively. */  
Boolean ssh_mapping_remove_key_vl(SshMapping normal_set, 
                                  const void *key, size_t key_length,
                                  void **value_return, size_t *value_length,
                                  void **key_return, size_t *key_length_return)
{
  SshMappingVL set = (SshMappingVL) normal_set;
  unsigned long h, h1, h2;
  unsigned long flag, start;

  if (key_return != NULL)
    (*key_return) = NULL;
  if (key_length_return != NULL)
    (*key_length_return) = 0;

  if (!(set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH))
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE;  /* Empty set, not a member. */

  /* Calculate a hash value for the key. */
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        /* In case of integer keys, the key can be used directly. */
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, key_length);

  /* Guarantee that hash value is always greater than 1. */
  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);

  start = h1;
  
  while (1)
    {
      flag = set->t[h1].h;
      if (flag == h &&
          SSH_MAPPING_COMPARE_KEY_VL(set, h1, key, key_length))
        break;
      else if (flag == 0)
        return FALSE;
      MODULO_ADD(set->size, h1, h2);
      if (start == h1)
        return 0;
    }

  set->semi_empties++;
  set->t[h1].h = 1;

  /* Return the pointer to the value. */
  if (value_return)
    *value_return = set->t[h1].value;
  else
    {
      /* Store the pointer into context for later retrieval with
         ssh_mapping_copy_value_vl(). */
      if (set->remove_value && !(set->flags & SSH_MAPPING_FL_STORE_POINTERS))
        ssh_xfree(set->cached_value);
      set->cached_value = set->t[h1].value;
      set->cached_length = set->t[h1].value_length;
      set->remove_value = TRUE;
    }
  if (value_length)
    *value_length = set->t[h1].value_length;
  
  if (key_return)
    *key_return = set->t[h1].key.p;
  if (key_length_return)
    *key_length_return = set->t[h1].key_length;

  /* If integer keys are not defined, free the key also. */
  if (!(set->flags & (SSH_MAPPING_FL_INTEGER_KEY |
                      SSH_MAPPING_FL_STORE_POINTERS)))
    ssh_xfree(set->t[h1].key.p);  
  
  /* Decrease the size of the hash table if it appears 
     to be mostly empty. */
  
  /*  if (3*set->semi_empties > (set->size >> 3) + set->empties) */
  if (set->refresh_lock == FALSE &&
      set->semi_empties > (set->size >> 3))
    {
      if (set->size > SSH_MAPPING_MINIMUM_SIZE &&
          set->size - set->empties - set->semi_empties < (set->size >> 4))
        {
#ifdef PRIME_TABLE
          set->size_shift--;
          ssh_mapping_refresh_vl(set, prime_table[set->size_shift]);
#else
          ssh_mapping_refresh_vl(set, set->size >> 1);
#endif /* PRIME_TABLE */
        }
      else  
        ssh_mapping_refresh_vl(set, set->size);
    }
  
  return TRUE;
}


/* Variable length version of ssh_mapping_get. Allocates space for
   value, copies data and returns a pointer to it, along with it's
   size. It is callers responsibility to free it with ssh_xfree. */
Boolean ssh_mapping_get_vl(const SshMapping normal_set,
                           const void *key, size_t key_length,
                           void **value_return, size_t *value_length)
{
  SshMappingVL set = (SshMappingVL) normal_set;
  unsigned long h, h1, flag;
  unsigned long h2, start;

  if (!(set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH))
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE;  /* Empty set, not a member. */

  /* Calculate a hash value for the key. */
  if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
    {
      if (set->hash_function)
        h = set->hash_function(key, sizeof(unsigned long));
      else
        /* In case of integer keys, the key can be used directly. */
        h = *((unsigned long *)key);
    }
  else
    h = set->hash_function(key, key_length);

  /* Guarantee that hash value is always greater than 1. */
  if (h < 2)
    h += 2;

  REDUCE_HASH(set->size, h, h1, h2);

  flag = set->t[h1].h;

  if (flag == h &&
      SSH_MAPPING_COMPARE_KEY_VL(set, h1, key, key_length))
    {
      if (value_return)
        {
          *value_return = set->t[h1].value;
        }
      else
        {
          if (set->remove_value &&
              !(set->flags & SSH_MAPPING_FL_STORE_POINTERS))
            ssh_xfree(set->cached_value);
          set->cached_value = set->t[h1].value;
          set->cached_length = set->t[h1].value_length;
          set->remove_value = FALSE;
        }
      if (value_length)
        *value_length = set->t[h1].value_length;
      return TRUE;
    }
  else
    {
      if (flag == 0)
        return FALSE;
    }
  
  start = h1;
  
  while (1)
    {
      MODULO_ADD(set->size, h1, h2);
      flag = set->t[h1].h;
      if (flag == h &&
          SSH_MAPPING_COMPARE_KEY_VL(set, h1, key, key_length))
        {
          /* Return the value pointer if asked. */
          if (value_return)
            *value_return = set->t[h1].value;
          else
            {
              /* Copy this pointer into context. */
              if (set->remove_value &&
                  !(set->flags & SSH_MAPPING_FL_STORE_POINTERS))
                ssh_xfree(set->cached_value);
              set->cached_value = set->t[h1].value;
              set->cached_length = set->t[h1].value_length;
              set->remove_value = FALSE;
            }
          if (value_length)
            *value_length = set->t[h1].value_length;
          return TRUE;
        }
      else if (flag == 0)
        return FALSE;
      if (h1 == start)
        return FALSE;     
    }  
}


/* Variable length version of ssh_mapping_get_next. */

Boolean ssh_mapping_get_next_vl(SshMapping normal_set,
                                void **key_return, size_t *key_length,
                                void **value_return, size_t *value_length)
{
  SshMappingVL set = (SshMappingVL) normal_set;
  unsigned long i;

  if (!(set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH))
    ssh_mapping_fatal();
  
  if (set->size == set->empties + set->semi_empties)
    return FALSE; /* Empty set, nothing more found. */

  /* Loop through the hash array. */
  for (i = set->idx; i < set->size; i++)
    if (set->t[i].h > 1)
      {
        /* If a full entry was found, update the index. */
        set->idx = i + 1;

        /* If asked, return the key. */
        if (key_return)
          {
            if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
              *((unsigned long *)key_return) = set->t[i].key.i;
            else
              *key_return = set->t[i].key.p;
          }
        if (key_length)
          {
            if (set->flags & SSH_MAPPING_FL_INTEGER_KEY)
              *key_length = sizeof(unsigned long);
            else
              *key_length = set->t[i].key_length;
          }

        /* Return the value, is asked. */
        if (value_return)
          *value_return = set->t[i].value;
        else
          {
            /* If value_return was null, store this pointer into a
               context for possible retrieval with
               ssh_mapping_copy_value_vl() */
            if (set->remove_value &&
                !(set->flags & SSH_MAPPING_FL_STORE_POINTERS))
              ssh_xfree(set->cached_value);
            set->cached_value = set->t[i].value;
            set->cached_length = set->t[i].value_length;
            set->remove_value = FALSE;
          }
        if (value_length)
          *value_length = set->t[i].value_length;

        return TRUE;
      }

  return FALSE;
}

/* If ssh_mapping_get_vl or ssh_mapping_remove_vl was called with
   NULL value_return, the otherwise returned value is stored in
   the mapping. This function can be used to copy the value to
   a given buffer. If no value is cached in mapping context or if
   buffers size is wrong, this returns FALSE.  Otherwise TRUE. */
Boolean ssh_mapping_copy_value_vl(SshMapping normal_set,
                                  void *value_return, size_t value_length)
{
  SshMappingVL set = (SshMappingVL) normal_set;
  
  if (!(set->flags & SSH_MAPPING_FL_VARIABLE_LENGTH))
    return FALSE;
  
  if (set->cached_value == NULL || set->cached_length != value_length)
    return FALSE;

  memcpy(value_return, set->cached_value, value_length);

  if (set->remove_value &&
      !(set->flags & SSH_MAPPING_FL_STORE_POINTERS))
    ssh_xfree(set->cached_value);

  set->cached_value = NULL;
  set->cached_length = 0;      
  set->remove_value = FALSE;
  
  return TRUE;
}

/* Set refresh lock. */
Boolean ssh_mapping_set_refresh_lock(SshMapping set, Boolean flag)
{
  Boolean rv = set->refresh_lock;
  set->refresh_lock = flag;
  return rv;
}
     
