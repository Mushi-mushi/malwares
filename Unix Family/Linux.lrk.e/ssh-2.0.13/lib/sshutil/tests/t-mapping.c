/*

t-mapping.c

Author: Toni Tammisalo <ttammisa@acr.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved.

Tests for mapping.c

*/

#include "sshincludes.h"
#include "sshmapping.h"

#define KEY_L   20
#define VALUE_L 128

#define QUIET

/* Timer functions start_time() and get_time().
   start_time() takes system time and saves it in TimeContext
   -structure.  get_time() returns time elapsed since last
   start_time() called in the same context. */

typedef struct
{
  struct timeval realtime;
  double start_time;
} TimeContext;

void start_time(TimeContext *tc)
{
#ifdef HAVE_GETTIMEOFDAY
  gettimeofday(&tc->realtime, NULL);      
  tc->start_time = ((double)tc->realtime.tv_sec +
                    (double)tc->realtime.tv_usec/1000000.0);
#else  /* HAVE_GETTIMEOFDAY */
  tc->start_time = (double)(ssh_time());
#endif /* HAVE_GETTIMEOFDAY */
}

double get_time(TimeContext *tc)
{
  double t;
  
#ifdef HAVE_GETTIMEOFDAY
  gettimeofday(&tc->realtime, NULL);      
  t = ((double)tc->realtime.tv_sec +
       (double)tc->realtime.tv_usec/1000000.0);
#else  /* HAVE_GETTIMEOFDAY */
  t = ((double)(ssh_time())) + 0.000001;
#endif /* HAVE_GETTIMEOFDAY */

  return t - tc->start_time;
}



void hexdump(unsigned char *buf, size_t len)
{
  size_t i;

  printf("hexdump: ");
  for (i = 0; i < len; i++)
    {
      printf("%02x", buf[i]);
    }
  printf("\n");
}

unsigned int my_rand(void)
{
#if 0
  unsigned long my_time = ssh_time() ^ clock();
  return ((((random() >> 1) ^ (random() << 7)) ^ (random() % 8) ^
    (my_time << 2) ^ (my_time >> 8)) * random()) ^ random();
#else
  return random();
#endif
}

void fill_rand(unsigned char *buf, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      buf[i] = my_rand() & 0xff;
    }
}

#define MAX_KEYS 1000
unsigned char *keys[MAX_KEYS];
unsigned char *values[MAX_KEYS];
size_t val_len[MAX_KEYS];
size_t key_len[MAX_KEYS];
unsigned long seeds[MAX_KEYS];
int num_entries;

void clean_entries(int k_len, int v_len)
{
  int i, count;

  count = 0;
  
  for (i = 0; i < MAX_KEYS; i++)
    {
      if (seeds[i] != 0)
        {
          if (k_len != 0)
            ssh_xfree(keys[i]);
          ssh_xfree(values[i]);
          keys[i] = NULL;
          values[i] = NULL;
          seeds[i] = 0;

          count++;
        }
    }
  assert(count == num_entries);
  
  num_entries = 0;
}

Boolean add_entry(SshMapping set, unsigned long seed,
                  int k_len, int v_len, int idx, Boolean rval)
{
  unsigned char *key, *value;
  Boolean result;

  assert(idx < MAX_KEYS);
  
  assert(seed != 0);
  if (rval == FALSE)
    assert(seeds[idx] == 0);
  else
    assert(seeds[idx] == seed);

  /*
  srandom(seed);
  */

  seeds[idx] = seed;

#ifdef STORE_POINTERS
  assert(k_len != -1 && v_len != -1);
  
  if (rval == FALSE)
    {
      key_len[idx] = (size_t)k_len;
      
      if (k_len == 0)
        key = (unsigned char *)(&seeds[idx]);
      else
        {
          key = ssh_xmalloc(key_len[idx]);
          fill_rand(key, key_len[idx]);
          memcpy(key, &seeds[idx], sizeof(unsigned long));
        }      
      keys[idx] = key;
    }
  else
    {
      if (k_len == 0)
        key = (unsigned char *)(&seeds[idx]);
      else
        key = keys[idx];
    }
      

  val_len[idx] = (size_t)v_len;    

  value = ssh_xmalloc(val_len[idx]);
  if (rval == TRUE)
    ssh_xfree(values[idx]);
  values[idx] = value;
  fill_rand(value, val_len[idx]);

  result = ssh_mapping_put(set, key, value);
  
  if (result != rval)
    return FALSE;
  
  return TRUE;
#endif /* STORE_POINTERS */
  
  if (rval == FALSE)
    {
      if (k_len == -1)
        key_len[idx] = sizeof(unsigned long) + (random() % 100);
      else
        key_len[idx] = (size_t)k_len;
      
      if (k_len == 0)
        key = (unsigned char *)(&seeds[idx]);
      else
        {
          key = ssh_xmalloc(key_len[idx]);
          fill_rand(key, key_len[idx]);
          memcpy(key, &seeds[idx], sizeof(unsigned long));
        }      
      keys[idx] = key;
    }
  else
    {
      if (k_len == 0)
        key = (unsigned char *)(&seeds[idx]);
      else
        key = keys[idx];
    }
      

  if (v_len == -1)
    val_len[idx] = 10 + (random() % 1024);
  else
    val_len[idx] = (size_t)v_len;    
  
  value = ssh_xmalloc(val_len[idx]);
  if (rval == TRUE)
    ssh_xfree(values[idx]);
  values[idx] = value;
  fill_rand(value, val_len[idx]);

  if (v_len == -1)  
    result = ssh_mapping_put_vl(set, key, key_len[idx],
                                value, val_len[idx]);
  else
    result = ssh_mapping_put(set, key, value);

  if (result != rval)
    return FALSE;
  
  return TRUE;
}

Boolean check_entry(SshMapping set, int k_len, int v_len, int idx,
                    Boolean rval)
{
  unsigned char *value;
  size_t size;
  Boolean result;

  assert(idx < MAX_KEYS);

#ifdef STORE_POINTERS
  assert(v_len != -1 && k_len != -1);
  
  if (k_len == 0)
    result = ssh_mapping_get(set, &seeds[idx], &value);
  else
    result = ssh_mapping_get(set, keys[idx], &value);
  if (result != rval)
    return FALSE;
  
  if (value != values[idx])
    return FALSE;

  return TRUE;
#endif /* STORE_POINTERS */
  
  if (v_len == -1)
    {
      if (k_len == 0)
        result = ssh_mapping_get_vl(set, &seeds[idx], key_len[idx],
                                    (void **) &value, &size);
      else
        result = ssh_mapping_get_vl(set, keys[idx], key_len[idx],
                                    (void **) &value, &size);

      if (result != rval)
        return FALSE;
      
      if (size != val_len[idx])
        return FALSE;

      if (memcmp(value, values[idx], size) != 0)
        return FALSE;

      return TRUE;
    }
  
  value = ssh_xmalloc(val_len[idx]);
  
  if (k_len == 0)
    result = ssh_mapping_get(set, &seeds[idx], value);
  else
    result = ssh_mapping_get(set, keys[idx], value);
  if (result != rval)
    return FALSE;
  
  if (memcmp(value, values[idx], val_len[idx]) != 0)
    return FALSE;

  ssh_xfree(value);
  
  return TRUE;
}

Boolean remove_entry(SshMapping set, int k_len, int v_len, int idx,
                     Boolean rval)
{
  unsigned char *value;
  size_t size;
  Boolean result;

  assert(idx < MAX_KEYS);

#ifdef STORE_POINTERS
  assert(k_len != -1 && v_len != -1);

  if (k_len == 0)
    result = ssh_mapping_remove(set, &seeds[idx], &value);
  else
    result = ssh_mapping_remove(set, keys[idx], &value);
  if (result != rval)
    return FALSE;

  if (value != values[idx])
    return FALSE;

  ssh_xfree(values[idx]);
  values[idx] = NULL;
  if (k_len != 0)
    ssh_xfree(keys[idx]);
  keys[idx] = NULL;
  seeds[idx] = 0;

  return TRUE;
#endif /* STORE_POINTERS */
  
  if (v_len == -1)
    {
      if (k_len == 0)
        result = ssh_mapping_remove_vl(set, &seeds[idx], key_len[idx],
                                       (void **) &value, &size);
      else
        result = ssh_mapping_remove_vl(set, keys[idx], key_len[idx],
                                       (void **) &value, &size);

      if (result != rval)
        return FALSE;
      
      if (size != val_len[idx])
        return FALSE;

      if (memcmp(value, values[idx], size) != 0)
        return FALSE;

      ssh_xfree(value);

      ssh_xfree(values[idx]);
      values[idx] = NULL;
      if (k_len != 0)
        ssh_xfree(keys[idx]);
      keys[idx] = NULL;
      seeds[idx] = 0;
      
      return TRUE;
    }

  value = ssh_xmalloc(val_len[idx]);
  
  if (k_len == 0)
    result = ssh_mapping_remove(set, &seeds[idx], value);
  else
    result = ssh_mapping_remove(set, keys[idx], value);
  if (result != rval)
    return FALSE;

  if (memcmp(value, values[idx], val_len[idx]) != 0)
    return FALSE;

  ssh_xfree(values[idx]);
  values[idx] = NULL;
  if (k_len != 0)
    ssh_xfree(keys[idx]);
  keys[idx] = NULL;
  seeds[idx] = 0;

  ssh_xfree(value);
  
  return TRUE;
}
  

int test1(SshMapping m, int test_loops, int k_len, int v_len)
{
  unsigned int i, j, loop, state;
  unsigned long seed, count;
  Boolean value;

  num_entries = 0;
  count = 1;
  
  for (i = 0; i < MAX_KEYS; i++)
    {
      seeds[i] = 0;
      keys[i] = NULL;
      values[i] = NULL;
    }
  
  for (loop = 0; loop < test_loops; loop++)
    {
      /* srandom(loop); */
      state = (random() + loop) % 5;

      if (num_entries == 0)
        state = 0;

      if (num_entries >= MAX_KEYS)
        state = 2;
      
      switch (state)
        {
        case 4:
        case 0:
          if (num_entries >= MAX_KEYS)
              break;

          for (i = 0; i < MAX_KEYS; i++)
            {
              if (seeds[i] == 0)
                break;
            }
          assert(i < MAX_KEYS);
          num_entries++;
          
          seed = count++;
          assert(seed != 0);
          /* printf("%5d:  add    %8lu,  index %4d\n", loop, seed, i);  */
          value = add_entry(m, seed, k_len, v_len, i, FALSE);
          if (value == FALSE)
            {
              printf("ssh_mapping_add failed.\n");
              return 1;
            }
          break;

        case 1:
          if (num_entries == 0)
            break;

          /* Get one existing mapping from the set. */
          j = (random() % num_entries) + 1;

          for (i = 0; i < MAX_KEYS; i++)
            {
              if (seeds[i] != 0)                
                j--;
              if (j == 0)
                break;      
            }
          assert(i < MAX_KEYS);
          assert(seeds[i] != 0);

          /* printf("%5d:  get    %8lu,  index %4d\n", loop, seeds[i], i); */
          value = check_entry(m, k_len, v_len, i, TRUE);
          if (value == FALSE)
            {
              printf("ssh_mapping_get failed.\n");
              return 2;
            }
          break;
          
        case 2:
          if (num_entries == 0)
            break;

          /* Get one existing mapping from the set. */
          j = (random() % num_entries) + 1;

          for (i = 0; i < MAX_KEYS; i++)
            {
              if (seeds[i] != 0)
                {
                  if (--j < 2)
                    break;
                }
            }     
          assert(seeds[i] != 0);
          assert(i < MAX_KEYS);
          num_entries--;

          /* printf("%5d:  remove %8lu,  index %4d\n", loop, seeds[i], i); */
          value = remove_entry(m, k_len, v_len, i, TRUE);
          if (value == FALSE)
            {
              printf("ssh_mapping_remove failed.\n");
              return 3;
            }
          break;

        case 3:
          if (num_entries == 0)
            break;
          
          /* Get one existing mapping from the set. */
          j = (random() % num_entries) + 1;

          for (i = 0; i < MAX_KEYS; i++)
            {
              if (seeds[i] != 0)
                {
                  if (--j < 2)
                    break;
                }
            }
          assert(i < MAX_KEYS);
          assert(seeds[i] != 0);

          /* printf("%5d:  add 2  %8lu,  index %4d\n", loop, seeds[i], i); */
          value = add_entry(m, seeds[i], k_len, v_len, i, TRUE);
          if (value == FALSE)
            {
              printf("ssh_mapping_add failed.\n");
              return 4;
            }
          break;
                          
        default:
          printf("Test program thinks too much.\n");
          break;
        }      
    }

  clean_entries(k_len, v_len);
  
  return 0;
}


unsigned long my_hash_function(const void *key,
                               const size_t key_length)
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

unsigned long bad_key(unsigned long x)
{
  return ((x >> 16) | (x << 16)) & 0xffffffff;
}


#define KEY_ARRAY 20000

int test2(int start_adds, int test_loops)
{
  SshMapping m;
  unsigned int loop, state;
  long count, keys_in_array, n;
  unsigned long key[KEY_ARRAY], head, tail, idx;
  void *p;
  Boolean value;
  TimeContext tc;
  double t;
  
  memset(key, 0, KEY_ARRAY * sizeof(unsigned long));
  keys_in_array = 0;
  head = 0;
  tail = 0;
  count = 1;

  m = ssh_mapping_allocate_with_func(SSH_MAPPING_FL_INTEGER_KEY |
                                     SSH_MAPPING_FL_STORE_POINTERS,
                                     NULL, NULL, NULL, 0, 0);
  if (!m)
    {
      printf("ssh_mapping_allocate_with_func failed.\n");
      return 1;
    }

  if (start_adds > KEY_ARRAY)
    start_adds = KEY_ARRAY;

  
  start_time(&tc);
  for (loop = 0; loop < start_adds; loop++)
    {
      key[head] = count++;
      value = ssh_mapping_put(m, &key[head], (void *)(key[head] + 100));
      if (value == TRUE)
        {
          printf("ssh_mapping_put failed, loop 1,%d\n", loop);
          return 2;
        }
      head++;
      keys_in_array++;
      if (head == KEY_ARRAY)
        head = 0;
      assert(head != tail);
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("added %5d keys to mapping, time %5.3f [%6.2f adds/sec]\n",
         start_adds, t, ((double)start_adds)/t);
#endif
  
  start_time(&tc);
  for (loop = 0; loop < test_loops; loop++)
    {
      state = random() % 3;

      if (keys_in_array >= KEY_ARRAY)
        state = 0;
      if (keys_in_array == 0)
        state = 1;

      switch (state)
        {
        case 0:
          key[head] = count++;
          value = ssh_mapping_put(m, &key[head], (void *)(key[head] + 100));
          if (value == TRUE)
            {         
              printf("ssh_mapping_put failed, loop 2,%d\n", loop);
              return 2;
            }
          head++;
          keys_in_array++;
          if (head == KEY_ARRAY)
            head = 0;
          assert(head != tail);
          break;

        case 1:
          value = ssh_mapping_remove(m, &key[tail], &p);
          if (value == FALSE)
            {
              printf("ssh_mapping_remove failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long) p != key[tail] + 100)
            {
              printf("ssh_mapping_remove failed (2), loop 2,%d \n", loop);
              return 2;
            }
          key[tail] = 0;          
          keys_in_array--;        
          tail++;
          if (tail == KEY_ARRAY)
            tail = 0;
          break;

        case 2:
          idx = random() % keys_in_array;
          if (tail + idx < KEY_ARRAY)
            idx += tail;
          else
            idx -= KEY_ARRAY - tail;
          
          value = ssh_mapping_get(m, &key[idx], &p);
          if (value == FALSE)
            {
              printf("ssh_mapping_get failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long)p != key[idx] + 100)
            {
              printf("ssh_mapping_get failed (2), loop 2,%d \n", loop);
              return 2;
            }
          break;

        default:
          printf("Invalid state.\n");
          return 1000;
        }      
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("%5d random ops., time %5.3f [%6.2f ops/sec]\n",
         test_loops, t, ((double)test_loops)/t);
#endif
  
  start_time(&tc);
  n = 0;
  for (loop = 0; loop < 100; loop++)
    {
      count = 0;
      ssh_mapping_reset_index(m);
      while (ssh_mapping_get_next(m, &idx, &p) == TRUE)
        {
          count++;
          if ((unsigned long) p != idx + 100)
            {
              printf("ssh_mapping_get_next failed. count %lu.\n", count);
              return 3;
            }
        }
      n += count;
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("Linear search: %lu keys in mapping, time %5.3f [%6.2f calls/sec]\n",
         count, t, ((double)n)/t);
#endif
  
  if (count != keys_in_array)
    {
      printf("Mismatch: only %lu keys in array.\n", keys_in_array);
      return 9;
    }
  
  ssh_mapping_free(m);
  
  return 0;
}

void fill_value(unsigned long key, unsigned char *buf, size_t len)
{
  unsigned char c;
  int i;

  c = (unsigned char) key;
  for (i = 0; i < len; i++)
    buf[i] = c++;     
}

Boolean check_value(unsigned long key, unsigned char *buf, size_t len)
{
  unsigned char c;
  int i;

  c = (unsigned char) key;
  for (i = 0; i < len; i++)
    {
      if (buf[i] != c++)
        return FALSE;
    }

  return TRUE;
}

int test3(int start_adds, int test_loops)
{
  SshMapping m;
  unsigned int loop, state;
  long count, keys_in_array, n;
  unsigned long key[KEY_ARRAY], head, tail, idx;
  unsigned char buf[256];
  size_t size;
  Boolean value;
  TimeContext tc;
  double t;
  
  memset(key, 0, KEY_ARRAY * sizeof(unsigned long));
  keys_in_array = 0;
  head = 0;
  tail = 0;
  count = 1;

  m = ssh_mapping_allocate_with_func(SSH_MAPPING_FL_INTEGER_KEY |
                                     SSH_MAPPING_FL_VARIABLE_LENGTH,
                                     NULL, NULL, NULL, 0, 0);
  if (!m)
    {
      printf("ssh_mapping_allocate_with_func failed.\n");
      return 1;
    }

  if (start_adds > KEY_ARRAY)
    start_adds = KEY_ARRAY;

  
  start_time(&tc);
  for (loop = 0; loop < start_adds; loop++)
    {
      key[head] = count++;
      fill_value(key[head], buf, 100);
      value = ssh_mapping_put_vl(m, &key[head], 0, buf, 100);
      if (value == TRUE)
        {
          printf("ssh_mapping_put failed, loop 1,%d\n", loop);
          return 2;
        }
      head++;
      keys_in_array++;
      if (head == KEY_ARRAY)
        head = 0;
      assert(head != tail);
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("added %5d keys to mapping, time %5.3f [%6.2f adds/sec]\n",
         start_adds, t, ((double)start_adds)/t);
#endif
  
  start_time(&tc);
  for (loop = 0; loop < test_loops; loop++)
    {
      state = random() % 3;

      if (keys_in_array >= KEY_ARRAY)
        state = 0;
      if (keys_in_array == 0)
        state = 1;

      switch (state)
        {
        case 0:
          key[head] = count++;
          fill_value(key[head], buf, 100);
          value = ssh_mapping_put_vl(m, &key[head], 0, buf, 100);
          if (value == TRUE)
            {         
              printf("ssh_mapping_put_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          head++;
          keys_in_array++;
          if (head == KEY_ARRAY)
            head = 0;
          assert(head != tail);
          break;

        case 1:
          value = ssh_mapping_remove_vl(m, &key[tail], 0, NULL, &size);
          if (value == FALSE)
            {
              printf("ssh_mapping_remove_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          if (size != 100)
            {
              printf("ssh_mapping_remove_vl returned wrong size.\n");
              return 2;
            }

          value = ssh_mapping_copy_value_vl(m, buf, size);
          if (value == FALSE)
            {
              printf("ssh_mapping_copy_value_vl failed.\n");
              return 2;
            }     
          if (check_value(key[tail], buf, 100) == FALSE)
            {
              printf("ssh_mapping_copy_value_vl returned wrong data.\n");
              return 2;
            }

          key[tail] = 0;          
          keys_in_array--;        
          tail++;
          if (tail == KEY_ARRAY)
            tail = 0;
          break;

        case 2:
          idx = random() % keys_in_array;
          if (tail + idx < KEY_ARRAY)
            idx += tail;
          else
            idx -= KEY_ARRAY - tail;
          
          value = ssh_mapping_get_vl(m, &key[idx], 0, NULL, &size);
          if (value == FALSE)
            {
              printf("ssh_mapping_get_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          if (size != 100)
            {
              printf("ssh_mapping_get_vl returned wrong size.\n");
              return 2;
            }

          value = ssh_mapping_copy_value_vl(m, buf, size);
          if (value == FALSE)
            {
              printf("ssh_mapping_copy_value_vl failed.\n");
              return 2;
            }     
          if (check_value(key[idx], buf, 100) == FALSE)
            {
              printf("ssh_mapping_copy_value_vl returned wrong data.\n");
              return 2;
            }
          break;

        default:
          printf("Invalid state.\n");
          return 1000;
        }      
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("%5d random ops., time %5.3f [%6.2f ops/sec]\n",
         test_loops, t, ((double)test_loops)/t);
#endif
  
  start_time(&tc);
  n = 0;
  for (loop = 0; loop < 100; loop++)
    {
      count = 0;
      ssh_mapping_reset_index(m);
      while (ssh_mapping_get_next_vl(m, (void **) &idx, 0, NULL, &size))
        {
          count++;
          if (size != 100)
            {
              printf("ssh_mapping_get_next_vl returned wrong size.\n");
              return 3;
            }

          value = ssh_mapping_copy_value_vl(m, buf, size);
          if (value == FALSE)
            {
              printf("ssh_mapping_copy_value_vl failed.\n");
              return 3;
            }     
          if (check_value(idx, buf, 100) == FALSE)
            {
              printf("ssh_mapping_copy_value_vl returned wrong data.\n");
              return 4;
            }
        }
      n += count;
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("Linear search: %lu keys in mapping, time %5.3f [%6.2f calls/sec]\n",
         count, t, ((double)n)/t);
#endif
  
  if (count != keys_in_array)
    {
      printf("Mismatch: only %lu keys in array.\n", keys_in_array);
      return 9;
    }
  
  ssh_mapping_free(m);
  
  return 0;
}


int test4(int start_adds, int test_loops)
{
  SshMapping m;
  unsigned int loop, state;
  long count, keys_in_array, n;
  unsigned long key[KEY_ARRAY], head, tail, idx;
  void *p, *k;
  Boolean value;
  TimeContext tc;
  double t;
  
  memset(key, 0, KEY_ARRAY * sizeof(unsigned long));
  keys_in_array = 0;
  head = 0;
  tail = 0;
  count = 1;

  m = ssh_mapping_allocate(SSH_MAPPING_TYPE_POINTER, sizeof(unsigned long),
                           0);
  if (!m)
    {
      printf("ssh_mapping_allocate failed.\n");
      return 1;
    }

  if (start_adds > KEY_ARRAY)
    start_adds = KEY_ARRAY;

  
  start_time(&tc);
  for (loop = 0; loop < start_adds; loop++)
    {
      key[head] = count++;
      value = ssh_mapping_put(m, &key[head], (void *)(key[head] + 100));
      if (value == TRUE)
        {
          printf("ssh_mapping_put failed, loop 1,%d\n", loop);
          return 2;
        }
      head++;
      keys_in_array++;
      if (head == KEY_ARRAY)
        head = 0;
      assert(head != tail);
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("added %5d keys to mapping, time %5.3f [%6.2f adds/sec]\n",
         start_adds, t, ((double)start_adds)/t);
#endif
  
  start_time(&tc);
  for (loop = 0; loop < test_loops; loop++)
    {
      state = random() % 3;

      if (keys_in_array >= KEY_ARRAY)
        state = 0;
      if (keys_in_array == 0)
        state = 1;

      switch (state)
        {
        case 0:
          key[head] = count++;
          value = ssh_mapping_put(m, &key[head],
                                  (void *)(key[head] + 100));
          if (value == TRUE)
            {         
              printf("ssh_mapping_put failed, loop 2,%d\n", loop);
              return 2;
            }
          head++;
          keys_in_array++;
          if (head == KEY_ARRAY)
            head = 0;
          assert(head != tail);
          break;

        case 1:
          value = ssh_mapping_remove(m, &key[tail], &p);
          if (value == FALSE)
            {
              printf("ssh_mapping_remove failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long) p != key[tail] + 100)
            {
              printf("ssh_mapping_remove failed (2), loop 2,%d \n", loop);
              return 2;
            }
          key[tail] = 0;          
          keys_in_array--;        
          tail++;
          if (tail == KEY_ARRAY)
            tail = 0;
          break;

        case 2:
          idx = random() % keys_in_array;
          if (tail + idx < KEY_ARRAY)
            idx += tail;
          else
            idx -= KEY_ARRAY - tail;
          
          value = ssh_mapping_get(m, &key[idx], &p);
          if (value == FALSE)
            {
              printf("ssh_mapping_get failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long)p != key[idx] + 100)
            {
              printf("ssh_mapping_get failed (2), loop 2,%d \n", loop);
              return 2;
            }
          break;

        default:
          printf("Invalid state.\n");
          return 1000;
        }      
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("%5d random ops., time %5.3f [%6.2f ops/sec]\n",
         test_loops, t, ((double)test_loops)/t);
#endif
  
  start_time(&tc);
  n = 0;
  for (loop = 0; loop < 100; loop++)
    {
      count = 0;
      ssh_mapping_reset_index(m);
      while (ssh_mapping_get_next(m, &k, &p) == TRUE)
        {
          count++;
          if ((unsigned long) p != *((unsigned long *)k) + 100)
            {
              printf("ssh_mapping_get_next failed. count %lu.\n", count);
              printf("index %p != value %p\n",
                     (void *)((unsigned long)k + 100), p);
              return 3;
            }
        }
      n += count;
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("Linear search: %lu keys in mapping, time %5.3f [%6.2f calls/sec]\n",
         count, t, ((double)n)/t);
#endif
  
  if (count != keys_in_array)
    {
      printf("Mismatch: only %lu keys in array.\n", keys_in_array);
      return 9;
    }
  
  ssh_mapping_free(m);
  
  return 0;
}


int test5(int start_adds, int test_loops)
{
  SshMapping m;
  unsigned int loop, state;
  long count, keys_in_array, n;
  unsigned long key[KEY_ARRAY], head, tail, idx;
  size_t key_l, val_l;
  void *p, *k;
  Boolean value;
  TimeContext tc;
  double t;
  
  memset(key, 0, KEY_ARRAY * sizeof(unsigned long));
  keys_in_array = 0;
  head = 0;
  tail = 0;
  count = 1;

  m = ssh_mapping_allocate(SSH_MAPPING_TYPE_POINTER_VL, 0, 0);
  if (!m)
    {
      printf("ssh_mapping_allocate failed.\n");
      return 1;
    }

  if (start_adds > KEY_ARRAY)
    start_adds = KEY_ARRAY;

  
  start_time(&tc);
  for (loop = 0; loop < start_adds; loop++)
    {
      key[head] = count++;
      value = ssh_mapping_put_vl(m, &key[head], sizeof(unsigned long),
                                 (void *)(key[head] + 100),
                                 (key[head] % 1024) + 1);
      if (value == TRUE)
        {
          printf("ssh_mapping_put_vl failed, loop 1,%d\n", loop);
          return 2;
        }
      head++;
      keys_in_array++;
      if (head == KEY_ARRAY)
        head = 0;
      assert(head != tail);
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("added %5d keys to mapping, time %5.3f [%6.2f adds/sec]\n",
         start_adds, t, ((double)start_adds)/t);
#endif
  
  start_time(&tc);
  for (loop = 0; loop < test_loops; loop++)
    {
      state = random() % 3;

      if (keys_in_array >= KEY_ARRAY)
        state = 0;
      if (keys_in_array == 0)
        state = 1;

      switch (state)
        {
        case 0:
          key[head] = count++;
          value = ssh_mapping_put_vl(m, &key[head], sizeof(unsigned long),
                                     (void *)(key[head] + 100),
                                     (key[head] % 1024) + 1);
          if (value == TRUE)
            {         
              printf("ssh_mapping_put_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          head++;
          keys_in_array++;
          if (head == KEY_ARRAY)
            head = 0;
          assert(head != tail);
          break;

        case 1:
          value = ssh_mapping_remove_vl(m, &key[tail], sizeof(unsigned long),
                                        &p, &val_l);
          if (value == FALSE)
            {
              printf("ssh_mapping_remove_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long) p != key[tail] + 100)
            {
              printf("ssh_mapping_remove_vl failed (2), loop 2,%d \n", loop);
              return 2;
            }
          if (val_l != (key[tail] % 1024) + 1)
            {
              printf("ssh_mapping_remove_vl failed (2), loop 2,%d \n", loop);
              return 2;
            }

          key[tail] = 0;          
          keys_in_array--;        
          tail++;
          if (tail == KEY_ARRAY)
            tail = 0;
          break;

        case 2:
          idx = random() % keys_in_array;
          if (tail + idx < KEY_ARRAY)
            idx += tail;
          else
            idx -= KEY_ARRAY - tail;
          
          value = ssh_mapping_get_vl(m, &key[idx], sizeof(unsigned long),
                                     &p, &val_l);
          if (value == FALSE)
            {
              printf("ssh_mapping_get_vl failed, loop 2,%d\n", loop);
              return 2;
            }
          if ((unsigned long)p != key[idx] + 100)
            {
              printf("ssh_mapping_get_vl failed (2), loop 2,%d \n", loop);
              return 2;
            }
          if (val_l != (key[idx] % 1024) + 1)
            {
              printf("ssh_mapping_get_vl failed (2), loop 2,%d \n", loop);
              return 2;
            }
          break;

        default:
          printf("Invalid state.\n");
          return 1000;
        }      
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("%5d random ops., time %5.3f [%6.2f ops/sec]\n",
         test_loops, t, ((double)test_loops)/t);
#endif
  
  start_time(&tc);
  n = 0;
  for (loop = 0; loop < 100; loop++)
    {
      count = 0;
      ssh_mapping_reset_index(m);
      while (ssh_mapping_get_next_vl(m, (void **) &k, &key_l, &p, &val_l)
             == TRUE)
        {
          count++;
          if ((unsigned long) p != *((unsigned long *)k) + 100)
            {
              printf("ssh_mapping_get_next_vl failed. count %lu.\n", count);
              return 3;
            }
          if (val_l != (*((unsigned long *)k) % 1024) + 1)
            {
              printf("ssh_mapping_get_next_vl failed (2), loop 2,%d \n", loop);
              return 2;
            }
        }
      n += count;
    }
  t = get_time(&tc);

#ifndef QUIET
  printf("Linear search: %lu keys in mapping, time %5.3f [%6.2f calls/sec]\n",
         count, t, ((double)n)/t);
#endif
  
  if (count != keys_in_array)
    {
      printf("Mismatch: only %lu keys in array.\n", keys_in_array);
      return 9;
    }
  
  ssh_mapping_free(m);
  
  return 0;
}


#define NUM_TESTS 10000

unsigned long my_hash_func(const void *key, const size_t size)
{
  return *((unsigned long *)key);
}

int my_compare_func(const void *key1, const void *key2,
                    const size_t length)
{
  return memcmp(key1, key2, length);
}
  

int main(void)
{
  TimeContext tc;
  SshMapping context;
  double t;
  int r; 
  
  srandom(ssh_time());
  srandom(42);
  
#ifdef STORE_POINTERS
#ifndef QUIET
  printf("Testing 'store pointers' mapping.\n");
#endif
  context = ssh_mapping_allocate_with_func(SSH_MAPPING_FL_INTEGER_KEY |      
                                           SSH_MAPPING_FL_STORE_POINTERS,
                                           my_hash_func, my_compare_func,
                                           NULL, 100, 1024);
  if (!context)
    {
      printf("ssh_mapping_allocate_with_func failed.\n");
      return 42;
    }

  printf("Performing %d tests operations... ", NUM_TESTS);  
  start_time(&tc);
  r = test1(context, NUM_TESTS, 50, 1024);  
  if (r != 0)
    return r;
  t = get_time(&tc);

#ifndef QUIET 
  printf("ok. [time: %4.1f sec;  %6.2f ops/sec]\n\n",
         t, (double)NUM_TESTS/t);
#endif
  ssh_mapping_free(context);

  return 0;
#endif /* STORE_POINTERS */

  /* Test fixed length mapping. */
#ifndef QUIET
  printf("Testing fixed length mapping.\n");
#endif
  context = ssh_mapping_allocate(SSH_MAPPING_TYPE_FIXED, 20, 120);
  if (!context)
    {
      printf("failed to allocate fixed length mapping.\n");
      return 42;
    }
  
#ifndef QUIET
  printf("Performing %d tests operations... ", NUM_TESTS);
#endif
  start_time(&tc);
  r = test1(context, NUM_TESTS, 20, 120);  
  if (r != 0)
    return r;
  t = get_time(&tc);

#ifndef QUIET
  printf("ok. [time: %4.1f sec;  %6.2f ops/sec]\n\n",
         t, (double)NUM_TESTS/t);
#endif
  ssh_mapping_free(context);

  /* Test variable length mapping. */
#ifndef QUIET
  printf("Testing variable length mapping.\n");
#endif
  context = ssh_mapping_allocate(SSH_MAPPING_TYPE_VARIABLE, 20, 120);
  if (!context)
    {
      printf("failed to allocate variable length mapping.\n");
      return 42;
    }

#ifndef QUIET
  printf("Performing %d tests operations... ", NUM_TESTS);
#endif
  start_time(&tc);
  r = test1(context, NUM_TESTS, -1, -1);  
  if (r != 0)
    return r;
  t = get_time(&tc);

#ifndef QUIET
  printf("ok. [time: %4.1f sec;  %6.2f ops/sec]\n\n",
         t, (double)NUM_TESTS/t);
#endif
  ssh_mapping_free(context);

  /* Test fixed length mapping with integer keys. */
#ifndef QUIET
  printf("Testing fixed length mapping with integer keys.\n");
#endif
  context = ssh_mapping_allocate(SSH_MAPPING_TYPE_INTEGER, 20, 120);
  if (!context)
    {
      printf("failed to allocate integer mapping.\n");
      return 42;
    }
  
#ifndef QUIET
  printf("Performing %d tests operations... ", NUM_TESTS);
#endif
  start_time(&tc);
  r = test1(context, NUM_TESTS, 0, 120);  
  if (r != 0)
    return r;
  t = get_time(&tc);

#ifndef QUIET
  printf("ok. [time: %4.1f sec;  %6.2f ops/sec]\n\n",
         t, (double)NUM_TESTS/t);
#endif
  ssh_mapping_free(context);

#ifndef QUIET
  printf("Performing benchmark with integer keyed store pointers set.\n");
#endif
  r = test2(10000, 100000);
  if (r != 0)
    return r;

#ifndef QUIET
  printf("Performing vl test with copied data.\n");
#endif
  r = test3(5000, 10000);
  if (r != 0)
    return r;

#ifndef QUIET
  printf("Performing benchmark with store pointers set.\n");
#endif
  r = test4(5000, 50000);
  if (r != 0)
    return r;

#ifndef QUIET
  printf("Performing benchmark with store pointers vl set.\n");
#endif
  r = test5(5000, 50000);
  if (r != 0)
    return r;

  return 0;
}
