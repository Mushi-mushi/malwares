/*

t-compress.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

#include "sshincludes.h"
#include "bufzip.h"
#include "namelist.h"

#define PASSES 1
#define MAX_SIZE 17000
#define STEP     31
#define REQUIRED_METHODS "none,zlib"

void test_compress(SshBuffer *b)
{
  unsigned int i, padlen;
  char *orig_methods, *method;
  const char *methods;
  SshBuffer *compressed, *uncompressed;
  unsigned char ch;
  SshCompression z_compress, z_uncompress;

  compressed = ssh_buffer_allocate();
  uncompressed = ssh_buffer_allocate();

  orig_methods = ssh_compress_get_supported();
  for (methods = orig_methods;
       (method = ssh_name_list_get_name(methods)) != NULL;
       methods = ssh_name_list_step_forward(methods))
    {
      ssh_buffer_clear(compressed);
      ssh_buffer_clear(uncompressed);

      padlen = random() % 10;
      ch = random();
      for (i = 0; i < padlen; i++)
	{
	  ssh_buffer_append(compressed, &ch, 1);
	  ssh_buffer_append(uncompressed, &ch, 1);
	}
      
      z_compress = ssh_compress_allocate(method, TRUE);
      z_uncompress = ssh_compress_allocate(method, FALSE);

      if (strcmp(method, "none") == 0)
	{
	  if (!ssh_compress_is_none(z_compress) ||
	      !ssh_compress_is_none(z_uncompress))
	    ssh_fatal("ssh_compress_is_none fails for none.");
	}
      else
	{
	  if (ssh_compress_is_none(z_compress) ||
	      ssh_compress_is_none(z_uncompress))
	    ssh_fatal("ssh_compress_is_none fails for !none.");
	}

      /* Test that compression works. */
      ssh_compress_buffer(z_compress, ssh_buffer_ptr(b), ssh_buffer_len(b),
			  compressed);
      ssh_buffer_consume(compressed, padlen);
      
      ssh_compress_buffer(z_uncompress, ssh_buffer_ptr(compressed),
			  ssh_buffer_len(compressed), uncompressed);
      ssh_buffer_consume(uncompressed, padlen);

      if (ssh_buffer_len(uncompressed) != ssh_buffer_len(b))
	ssh_fatal("SshBuffer length differs after uncompression.");

      if (memcmp(ssh_buffer_ptr(uncompressed), ssh_buffer_ptr(b), ssh_buffer_len(b)) != 0)
	ssh_fatal("SshBuffer data differs after uncompression.");

      /* Now compress again with the same context to check that it works. */
      ssh_buffer_clear(compressed);
      ssh_buffer_clear(uncompressed);
      ssh_compress_buffer(z_compress, ssh_buffer_ptr(b), ssh_buffer_len(b),
			  compressed);
      ssh_compress_buffer(z_uncompress, ssh_buffer_ptr(compressed),
			  ssh_buffer_len(compressed), uncompressed);
      if (ssh_buffer_len(uncompressed) != ssh_buffer_len(b))
	ssh_fatal("SshBuffer length differs after second uncompression.");
      if (memcmp(ssh_buffer_ptr(uncompressed), ssh_buffer_ptr(b), ssh_buffer_len(b)) != 0)
	ssh_fatal("SshBuffer data differs after second uncompression.");

      ssh_compress_free(z_compress);
      ssh_compress_free(z_uncompress);
      ssh_xfree(method);
    }
      
  ssh_buffer_free(compressed);
  ssh_buffer_free(uncompressed);
  ssh_xfree(orig_methods);
}

int main(int ac, char **av)
{
  int pass, len, i;
  unsigned char ch;
  SshBuffer *b;
  char *cp, *cp2;

  b = ssh_buffer_allocate();
  
  for (pass = 0; pass < PASSES; pass++)
    {
      printf("pass %d\n", pass);
      cp = ssh_compress_get_supported();
      cp2 = ssh_name_list_intersection(REQUIRED_METHODS, cp);
      if (strcmp(cp2, REQUIRED_METHODS) != 0)
	ssh_fatal("Required compression methods missing; got %s, expected %s",
		  cp, REQUIRED_METHODS);
      ssh_xfree(cp2);
      ssh_xfree(cp);

      printf("Running compression tests to %d:", MAX_SIZE);
      fflush(stdout);
      for (len = 1; len < MAX_SIZE; len += STEP)
	{
	  if (len % 256 == 0)
	    {
	      printf(" %d", len);
	      fflush(stdout);
	    }

	  /* Test compressing random data. */
	  ssh_buffer_clear(b);
	  for (i = 0; i < len; i++)
	    {
	      ch = random();
	      ssh_buffer_append(b, &ch, 1);
	    }
	  test_compress(b);

	  /* Test compressing sequentially increasing data. */
	  ssh_buffer_clear(b);
	  ch = random();
	  for (i = 0; i < len; i++)
	    {
	      ch++;
	      ssh_buffer_append(b, &ch, 1);
	    }
	  test_compress(b);

	  /* Test compressing data that is a single character repeated. */
	  ssh_buffer_clear(b);
	  ch = random();
	  for (i = 0; i < len; i++)
	    ssh_buffer_append(b, &ch, 1);
	  test_compress(b);

	  /* Test compressing data with random short segments. */
	  ssh_buffer_clear(b);
	  ch = random();
	  for (i = 0; i < len; i++)
	    {
	      if (random() % 5 == 0)
		ch = random();
	      ssh_buffer_append(b, &ch, 1);
	    }
	  test_compress(b);
	}
      printf("\n");
    }
  ssh_buffer_free(b);
  return 0;
}

/* XXX should test decompressing random data!  Need to add proper error
   handling in zlib! */
