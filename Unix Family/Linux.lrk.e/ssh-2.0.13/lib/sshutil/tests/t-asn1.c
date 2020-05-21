/*

  t-asn1.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Feb 24 16:48:04 1997 [mkojo]

  ASN.1 tester. Runs some tests that should be good enough for
  testing the ASN.1 code (i.e. parser if you like to call it that).

  What should be noted is that the ASN.1 code is not generic ASN.1 but
  a simplified subset. It features integrated BER/DER encoding.

  NOTES:

    - One significant problem (it seems) is that when traversing the
      ASN.1 tree one cannot go up! Thus we need some additional stuff for
      that which isn't nice. Going up should be implemented.
  
  */

/*
 * $Id: t-asn1.c,v 1.9 1999/04/29 13:39:03 huima Exp $
 * $Log: t-asn1.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmp.h" /* was "gmp.h" */
#include "sshasn1.h"

const char *classes[4] =
{
  "uni",
  "app",
  "ctx",
  "prv"
};

const char *encodings[2] =
{
  "prm",
  "cst"
};

const char *length_encodings[2] =
{
  "def",
  "ind",
};

const char *tags[32] =
{
  "reserved",    /* 0 */
  "boolean",     /* 1 */
  "integer",     /* 2 */
  "bit string",        /* 3 */
  "octet string",      /* 4 */
  "null",                /* 5 */
  "object identifier",    /* 6 */ 
  "ode",               /* 7 */
  "eti",               /* 8 */
  "real",              /* 9 */
  "enum",              /* 10 */
  "embedded",          /* 11 */
  "reserved",  "reserved",  "reserved",  "reserved", /* 12 13 14 15 */
  "sequence",  /* 16 */
  "set",       /* 17 */
  "numeric string",  /* 18 */
  "printable string",  /* 19 */
  "teletex string",    /* 20 */
  "videotex string",   /* 21 */
  "ia5 string",        /* 22 */
  "universal time",    /* 23 */
  "generalized time",  /* 24 */
  "graphic string",    /* 25 */
  "visible string",    /* 26 */
  "general string",     /* 27 */
  "universal string",    /* 28 */
  "unrestricted string",   /* 29 */
  "bmp string",          /* 30 */
  "reserved"           /* 31 */
};

unsigned int verbose;

const char *test_string_1 = "This is just a plain test string.";
const char *test_string_2 = "This is just another plain test string.";
const char *test_string_3 = "holabaloo.";
const char *test_string_4 = "When times are tough...";
const char *test_string_5 = "1";
const char *test_string_6 = "2";
const char *test_string_7 = "3";
const char *test_string_8 = "4";
const char *test_string_9 = "5";
const char *test_string_10 = "6";
const char *test_string_11 = "7";
const char *test_string_12 = "8";


void print_buf(unsigned char *buf, unsigned int length)
{
  int i;

  printf(" \"");
  for (i = 0; i < length; i++)
    {
      if (i > 0 && (i % 40) == 0)
        printf("\\  ");
      printf("%c", buf[i]);
    }
  printf("\"\n");
}

void print_hex(unsigned char *buf, unsigned int length)
{
  int i;

  if (length == 0)
    {
      printf("\n");
      return;
    }
  
  printf("  : ");
  for (i = 0; i < length; i++)
    {
      if (i > 0)
        printf(" ");
      if (i > 0 && (i % (75/3)) == 0)
        printf("\n  : ");
        
      printf("%02x", buf[i]);
    }
  printf("\n");
}

void print_node(int level, SshAsn1Node node)
{
  SshAsn1Class class;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length;
  unsigned char *data;
  SshAsn1Status status;
  int i;
  
  if ((status = ssh_asn1_node_get(node, &class, &encoding, &tag_number,
                                  &length_encoding,
                                  &length, &data)) != SSH_ASN1_STATUS_OK)
    {
      printf("error: status %d\n", status);
      exit(1);
    }
  
  printf("%04d ", length);

  if (class >= 0 && class < 4)
    printf(" %s", classes[class]);
  else
    printf(" %d", class);

  if (encoding >= 0 && encoding < 2)
    printf(" %s", encodings[encoding]);
  else
    printf(" %d", encoding);

  if (length_encoding >= 0 && length_encoding < 2)
    printf(" %s", length_encodings[length_encoding]);
  else
    printf(" %d", length_encoding);

  printf(": ");
  
  for (i = 0; i < level; i++)
    printf(". ");

  if (tag_number >= 0 && tag_number < 32 && class == SSH_ASN1_CLASS_UNIVERSAL)
    printf(" %s", tags[tag_number]);
  else
    printf(" %d", (unsigned int)tag_number);

  if (class == SSH_ASN1_CLASS_UNIVERSAL)
    switch (tag_number)
      {
      case SSH_ASN1_TAG_SET:
      case SSH_ASN1_TAG_SEQUENCE:
        printf("\n");
        break;
        
      case SSH_ASN1_TAG_OCTET_STRING:
      case SSH_ASN1_TAG_VISIBLE_STRING:
      case SSH_ASN1_TAG_PRINTABLE_STRING:
      case SSH_ASN1_TAG_TELETEX_STRING:
      case SSH_ASN1_TAG_IA5_STRING:
        print_buf(data, length);
        break;
      case SSH_ASN1_TAG_GENERALIZED_TIME:
      case SSH_ASN1_TAG_UNIVERSAL_TIME:
      default:
        printf("\n");
        print_hex(data, length);
        break;
      }
  else
    {
      printf("\n");
      print_hex(data, length);
    }
  
  /* Remember to free what you've allocated. */
  ssh_xfree(data);  
}

void print_tree(SshAsn1Tree tree)
{
  static int level = 0;

  do
    {
      print_node(level, ssh_asn1_get_current(tree));

      if (ssh_asn1_move_down(tree) == SSH_ASN1_STATUS_OK)
        {
          level++;
          print_tree(tree);
          level--;
          ssh_asn1_move_up(tree);
        }
    }
  while (ssh_asn1_move_forward(tree, 1));
}

void test(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  const unsigned char *string = (const unsigned char *) "my string";

  context = ssh_asn1_init();
  status = ssh_asn1_create_tree(context, &tree,
                                "(octet-string ())",
                                string, strlen((char *)string));

  printf("status %d\n", status);
  
  print_tree(tree);

  status = ssh_asn1_encode(context, tree);
  printf("status %d\n", status);

  print_tree(tree);

  ssh_asn1_free(context);
  
}

void test_1(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  unsigned char *data;
  size_t length;
  SshInt integer;
  char *oid = "1.2.840.113549.1";
  unsigned char bit_string[3] = { 0x6e, 0x5d, 0xc0 };

  ssh_mp_init_set_si(&integer, -129);

  /* Allocate context for asn1 work. */
  context = ssh_asn1_init();

  status = ssh_asn1_create_tree(context, &tree,
                            "(sequence () (boolean ()) (bit-string ())"
                            "(sequence () (octet-string ()) "
                            "(set () (object-identifier ()) (octet-string ())"
                            "(set () "
                                "(octet-string ()) (octet-string ())"
                                "(octet-string ()) "
                            "(octet-string ()))"
                            "(octet-string ()) (sequence ()"
                                "(octet-string())))"
                            "(octet-string ()) (integer ())))",
                            TRUE,
                            bit_string, 18,
                            test_string_1, strlen(test_string_1),
                            oid, 
                            test_string_2, strlen(test_string_2),
                            test_string_3, strlen(test_string_3),
                            test_string_4, strlen(test_string_4),
                            test_string_7, strlen(test_string_7),
                            test_string_8, strlen(test_string_8),
                            test_string_9, strlen(test_string_9),
                            test_string_10, strlen(test_string_10),
                            test_string_11, strlen(test_string_11),
                            &integer
                            );
  ssh_mp_clear(&integer);

  
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (1): status %d\n", status);
      exit(1);
    }

  /* Print the just created tree. */
  if (verbose)
    print_tree(tree);
  
  /* Do the encoding. */
  status = ssh_asn1_encode(context, tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2): status %d\n", status);
      exit(1);
    }
  
  /* Get the encoded BER data. */
  ssh_asn1_get_data(tree, &data, &length);
  
  /* Free the context and everything in it. */
  ssh_asn1_free(context);

  if (verbose)
    {
      printf("ASN.1 test_1 data : \n");
      print_hex(data, length);
      printf("\n");
    }

  /* Test reading it. */
  context = ssh_asn1_init();

  status = ssh_asn1_decode(context, data, length, &tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (3) status %d.\n", status);
      exit(1);
    }

  /* Print decoded tree. */
  if (verbose)
    print_tree(tree);
  
  ssh_asn1_free(context);

  /* Data could be freed after decode but done here :) */
  ssh_xfree(data);
}

void test_2(void)
{
  SshAsn1Context context;
  SshAsn1Status status;
  SshAsn1Tree tree;
  SshAsn1Node node;
  char *oid = "1.2.3234234.23423.34.3.23";
  SshInt int_1, int_2, int_3;
  unsigned char *data;
  size_t length;
  
  ssh_mp_init_set_ui(&int_1, 1);
  ssh_mp_init_set_ui(&int_2, 93842359);
  ssh_mp_init_set_ui(&int_3, 439223);

  /* Initialize the asn1 allocation context. */
  context = ssh_asn1_init();
  
  status = ssh_asn1_create_tree(context, &tree,
                            "(sequence (pe 1001)"
                                " (object-identifier (p 1238734))"
                                " (sequence (a 43) "
                            "(integer (a 1))"
                                "(integer (a 55)) (integer (a 129343556))))",
                            oid,
                            &int_1, &int_2, &int_3);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,1): status %d.\n", status);
      exit(1);
    }

  status = ssh_asn1_create_node(context, &node,
                            "(object-identifier ()) "
                                "(sequence () (integer ())"
                                " (integer ()) (integer ()))",
                            oid,
                            &int_1, &int_2, &int_3);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,2): status %d.\n", status);
      exit(1);
    }
  
  /* Find last in first row. */
  while (ssh_asn1_move_forward(tree, 1))
    ;
  
  status = ssh_asn1_insert_list(ssh_asn1_get_current(tree), NULL, node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,3): status %d.\n", status);
      exit(1);
    }

  ssh_asn1_reset_tree(tree);
  
  if (verbose)
    print_tree(tree);
  
  status = ssh_asn1_encode(context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (2,4): status %d.\n", status);
      exit(1);
    }

  ssh_asn1_get_data(tree, &data, &length);

  if (verbose)
    print_hex(data, length);

  ssh_asn1_free(context);

  ssh_xfree(data);
  
  ssh_mp_clear(&int_1);
  ssh_mp_clear(&int_2);
  ssh_mp_clear(&int_3);
}

void test_3(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  unsigned char data[] =
  {
    0x60, 0x81, 0x85,
    0x61, 0x10,
    0x1a, 0x04, 'J', 'o', 'h', 'n',
    0x1a, 0x01, 'P',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa0, 0x0a,
    0x1a, 0x08, 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r',
    0x42, 0x01, 0x33,
    0xa1, 0x0a,
    0x43, 0x08, '1', '9', '7', '1', '0', '9', '1', '7',
    0xa2, 0x12,
    0x61, 0x10,
    0x1a, 0x04, 'M', 'a', 'r', 'y',
    0x1a, 0x01, 'T',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa3, 0x42,
    0x31, 0x1f,
    0x61, 0x11,
    0x1a, 0x05, 'R', 'a', 'l', 'p', 'h',
    0x1a, 0x01, 'T',
    0x1a, 0x05, 'S', 'm', 'i', 't', 'h',
    0xa0, 0x0a,
    0x43, 0x08, '1', '9', '5', '7', '1', '1', '1', '1',
    0x31, 0x1f,
    0x61, 0x11,
    0x1a, 0x05, 'S', 'u', 's', 'a', 'n',
    0x1a, 0x01, 'B',
    0x1a, 0x05, 'J', 'o', 'n', 'e', 's',
    0xa0, 0x0a,
    0x43, 0x08, '1', '9', '5', '9', '0', '7', '1', '7',
  };

  /* Initialize the asn.1 context. */
  context = ssh_asn1_init();

  if (verbose)
    printf("Full length: %08x %d\n", sizeof(data) - 3, sizeof(data) - 3);
  
  status = ssh_asn1_decode(context, data, sizeof(data), &tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error (3, 1): status report %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);
  
  ssh_asn1_free(context);  
}

void test_4(void)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  Boolean boolean;
  unsigned char *new_str;
  unsigned int new_str_len;
  const unsigned char *string = (const unsigned char *)
    "Secret string not to be found.";
  const unsigned char *string_2 = (const unsigned char *)
    "Most things in life aren't free...";

  context = ssh_asn1_init();

  boolean = FALSE;
  
  status = ssh_asn1_create_tree(context, &tree,
                                "(sequence (a 50) (boolean (c 1))"
                                "(octet-string (c 2))"
                                "(sequence () (sequence () "
                                "(sequence (a 10) (octet-string (c 987))))))",
                                boolean, string, strlen((char *) string) + 1,
                                string_2, strlen((char *) string_2) + 1);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (4,1)\n");
      exit(1);
    }

  status = ssh_asn1_read_tree(tree, "(sequence (a 50) (sequence () "
                              "(sequence () "
                              "(sequence (a 10) (octet-string (c 987))))))",
                              &new_str, &new_str_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (4, 2)\n");
      exit(1);
    }

  if (verbose)
    printf("new_str: %s\n", new_str);
  
  ssh_xfree(new_str);
  
  status = ssh_asn1_search_tree(tree, "(octet-string (c 987))");

  if (status == SSH_ASN1_STATUS_OK)
    {
      status = ssh_asn1_read_node(ssh_asn1_get_current(tree),
                                  "(octet-string (c 987))",
                              &new_str, &new_str_len);

      if (status != SSH_ASN1_STATUS_OK)
        {
          printf("error: (4, 3)\n");
          exit(1);
        }

      if (verbose)
        printf("new_str: %s", new_str);
      ssh_xfree(new_str);
    }
  else
    {
      if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND)
        {
          printf("error: (4, 4) Could not locate.\n");
        }
      else
        {
          printf("error: (4, 5) %d.\n", status);
        }
      exit(1);
    }
      
  ssh_asn1_free(context);
}

void test_5(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshInt int_1, int_2, int_3, int_4, int_5, int_6, int_7, temp;
  char *oid = "1.2.840.113549.1";
  unsigned char bit_string[3] = { 0x6e, 0x5d, 0xc0 };
  char *my_oid;
  unsigned char *my_bs;
  unsigned int my_bs_len;
  int i;
  
  ssh_mp_init_set_ui(&int_1, 0);
  ssh_mp_init_set_ui(&int_2, 343);
  ssh_mp_init_set_si(&int_3, -4982735);
  ssh_mp_init_set_ui(&int_4, 545);
  ssh_mp_init_set_ui(&int_5, 541);
  ssh_mp_init_set_ui(&int_6, 55);
  ssh_mp_init_set_ui(&int_7, 9873245);
  ssh_mp_init_set_ui(&temp, 0);
  
  context = ssh_asn1_init();

  status =
    ssh_asn1_create_tree
    (context,
     &tree,
     "(sequence (a 1) "
       "(sequence (a 2) "
         "(integer (1)) (integer (2))"
         "(sequence (a 3)"
           "(integer (3))"
           "(sequence (a 4)"
             "(integer (4)))"
           "(sequence (a 4)"
             "(integer (5))))"
         "(integer (6)) (integer (7)) "
         "(object-identifier (20)) (bit-string (22))))",
     &int_1, &int_2, &int_3, &int_4, &int_5, &int_6, &int_7,
     oid, bit_string, 18);
  
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5,1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);

  status = ssh_asn1_search_tree(tree,
                                "(sequence (a 3) (integer (3)))");
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5,2) could not find. (%d)\n", status);
      exit(1);
    }

  status = ssh_asn1_read_node(ssh_asn1_get_current(tree),
                          "(sequence (a 3) (integer (3)))",
                          &temp);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5,3) could not find. (%d)\n", status);
      exit(1);
    }

  if (ssh_mp_cmp(&temp, &int_3) != 0)
    {
      printf("error: (5,4) not correct.\n");

      printf("\n");
      ssh_mp_out_str(NULL, 16, &temp);
      printf(" != ");
      ssh_mp_out_str(NULL, 16, &int_3);
      printf("\n");
      exit(1);
    }
  
  if (verbose)
    {
      printf("\n");
      ssh_mp_out_str(NULL, 16, &temp);
      printf(" = ");
      ssh_mp_out_str(NULL, 16, &int_3);
      printf("\n");
      printf("Found the correct one.\n");
    }

  /* Reset the current position... */
  ssh_asn1_reset_tree(tree);

  status = ssh_asn1_search_tree(tree, "(object-identifier (20))");

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5, 5) status %d\n", status);
      exit(1);
    }

  status = ssh_asn1_read_node(ssh_asn1_get_current(tree),
                          "(object-identifier (20))",
                          &my_oid);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5, 6) status %d\n", status);
      exit(1);
    }

  if (verbose)
    printf("Checking oids...\n");

  if (strcmp(my_oid, oid) != 0)
    {
      printf(" %s != %s\n", my_oid, oid);
      printf("error: (5, 7) not ok.\n");
      exit(1);
    }
  
  ssh_xfree(my_oid);
  
  if (verbose)
    printf("Oid ok.\n");
  
  /* Reset again... */
  ssh_asn1_reset_tree(tree);

  status = ssh_asn1_search_tree(tree, "(bit-string (22))");

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5, 8) status %d\n", status);
      exit(1);
    }

  status = ssh_asn1_read_node(ssh_asn1_get_current(tree),
                          "(bit-string (22))",
                          &my_bs, &my_bs_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (5, 8) status %d\n", status);
      exit(1);
    }

  if (verbose)
    printf("Checking bit strings...\n");
  
  for (i = 0; i < (my_bs_len + 7) / 8; i++)
    {
      if (verbose)
        printf("%02x == %02x\n", my_bs[i], bit_string[i]);
      
      if (my_bs[i] != bit_string[i])
        {
          printf("error: (5, 9)\n");
          exit(1);
        }
    }

  ssh_xfree(my_bs);
  
  if (verbose)
    printf("bs ok.\n");
  
  ssh_mp_clear(&temp);
    
  ssh_mp_clear(&int_1);
  ssh_mp_clear(&int_2);
  ssh_mp_clear(&int_3);
  ssh_mp_clear(&int_4);
  ssh_mp_clear(&int_5);
  ssh_mp_clear(&int_6);
  ssh_mp_clear(&int_7);
  ssh_asn1_free(context);
}

void test_6(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Node node;
  SshInt int_1, int_2, int_3, int_4, int_5, int_6, int_7, temp;
  
  ssh_mp_init_set_ui(&int_1, 9843841);
  ssh_mp_init_set_ui(&int_2, 343);
  ssh_mp_init_set_si(&int_3, -4982735);
  ssh_mp_init_set_ui(&int_4, 545);
  ssh_mp_init_set_ui(&int_5, 43541);
  ssh_mp_init_set_ui(&int_6, 55);
  ssh_mp_init_set_ui(&int_7, 9873245);
  ssh_mp_init_set_ui(&temp, 0);
  
  context = ssh_asn1_init();

  status =
    ssh_asn1_create_tree
    (context,
     &tree,
     "(sequence (a 1) "
       "(set (a 2) "
         "(integer (1)) "
         "(integer (1)) "
         "(integer (1)) (integer (1)) (integer (1))"
         "(integer (1)) (integer (1))))",
     &int_1, &int_2, &int_3, &int_4, &int_5, &int_6, &int_7);
  
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (6,1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);

  /* Sort to correct order! */

  status = ssh_asn1_search_tree(tree, "(set (a 2))");
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (6,2) %d.\n", status);
      exit(1);
    }

  if (ssh_asn1_move_down(tree) != SSH_ASN1_STATUS_OK)
    {
      printf("error: (6,3) %d.\n", status);
      exit(1);
    }

  node = ssh_asn1_sort_list(context, ssh_asn1_get_current(tree));
  if (node == NULL)
    {
      printf("error: (6,4) %d.\n", status);
      exit(1);
    }

  if (verbose)
    {
      ssh_asn1_reset_tree(tree);
      printf("Sorted...\n");
      print_tree(tree);
    }
  
  ssh_mp_clear(&temp);
    
  ssh_mp_clear(&int_1);
  ssh_mp_clear(&int_2);
  ssh_mp_clear(&int_3);
  ssh_mp_clear(&int_4);
  ssh_mp_clear(&int_5);
  ssh_mp_clear(&int_6);
  ssh_mp_clear(&int_7);
  ssh_asn1_free(context);
}

void test_7(void)
{
  SshAsn1Status status;
  SshAsn1Context context;
  SshAsn1Tree tree, tmp_tree;
  SshAsn1Node node, any;
  unsigned char *str_1, *str_2, *str_3;
  size_t str_1_len, str_2_len, str_3_len;
  unsigned int which1, which2;
  Boolean bool, found;

  context = ssh_asn1_init();
  
  status =
    ssh_asn1_create_tree
    (context, &tree,
     /* This is something which might look like what is rather complicated
        to parse in real life. */
     "(sequence ()"
     "(sequence (1) (octet-string (0)))"
     "(sequence ()"
       "(boolean ())"
       "(octet-string ()))"
     "(octet-string (4)))",
     test_string_1, strlen(test_string_1),
     1,
     test_string_2, strlen(test_string_2),
     test_string_3, strlen(test_string_3));

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 1) %d.\n", status);
      exit(1);
    }

  if (verbose)
    print_tree(tree);
  
  /* Now we show that reading from thus complicated object isn't really
     complicated. */
  status =
    ssh_asn1_read_tree
    (tree,
     "(sequence ()"
     /* Very simple objects can be selected by choice. */
     "(choice (sequence (0) (octet-string (1))) (sequence (1) (octet-string (0))))"
     /* For little bit more complex we suggest the any construct. */
     "(any ())"
     "(optional (octet-string (10)))"
     "(choice (octet-string (100)) (octet-string (4))))",
     &which1, &str_1, &str_1_len, &str_1, &str_1_len,
     &any,
     &found, &str_3, &str_3_len,
     &which2, &str_2, &str_2_len, &str_2, &str_2_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 2) %d.\n", status);
      exit(1);
    }

  tmp_tree = ssh_asn1_init_tree(context, any, any);
  
  if (verbose)
    {
      printf("Printing the any field.\n");
      print_tree(tmp_tree);
    }

  printf("Matches at: %d %d\n", which1, which2);
  
  printf("Read buffers: \n");
  print_buf(str_1, str_1_len);
  print_buf(str_2, str_2_len);

  ssh_xfree(str_1);
  ssh_xfree(str_2);
  
  status = ssh_asn1_read_node
    (any, 
     "(sequence ()"
     "(boolean ())"
     "(octet-string ()))",
     &bool,
     &str_1, &str_1_len);
  
  if (status != SSH_ASN1_STATUS_OK)
    {
      printf("error: (7, 3) %d.\n", status);
      exit(1);
    }
  
  print_buf(str_1, str_1_len);
  ssh_xfree(str_1);
  printf("bool %d\n", bool);

  ssh_asn1_free(context);
}

void main(void)
{
  test();

  verbose = 1;
  printf("\nTest 1.\n\n");
  test_1(); 
  printf("\nTest 2.\n\n");
  test_2(); 
  printf("\nTest 3.\n\n");
  test_3(); 
  printf("\nTest 4.\n\n");
  test_4();
  printf("\nTest 5.\n\n");
  test_5();
  printf("\nTest 6.\n\n");
  test_6();
  printf("\nTest 7.\n\n");
  test_7();
  printf("\nEnd.\n");
  exit(0);
}

