/*

  namelist.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Sep 28 16:41:22 1996 [mkojo]

  Computation of the intersection of two lists of names.

  */

/*
 * $Id: namelist.c,v 1.18 1999/03/15 15:20:26 tri Exp $
 * $Log: namelist.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "namelist.h"
#include "sshcstack.h"
#include "bufzip.h"

/* Tree based approach to parse and compare namelists. */

/* Internal status. */
typedef enum
{
  NTREE_ERROR,
  NTREE_OK,
  NTREE_REMOVE
} NTreeStatus;

/* Internal representation name tree nodes. */
struct SshNameNodeRec
{
  const char *identifier;
  size_t identifier_len;
  int identifier_set;
  struct SshNameNodeRec *next, *prev, *child, *parent;
};

/* Name tree. */
struct SshNameTreeRec
{
  SshNameNode root;
};

/* Allocation and setting up one node. */
SshNameNode ssh_nnode_allocate(void)
{
  SshNameNode node = ssh_xmalloc(sizeof(*node));
  node->identifier = NULL;
  node->identifier_len = 0;
  node->identifier_set = 1;
  node->next = node->prev = node->child = node->parent = NULL;
  return node;
}

/* Free one node from a tree, so that the tree will still be valid. */
void ssh_nnode_free(SshNameTree tree, SshNameNode this)
{
  SshNameNode temp, node = this->child;
  while (node && node != this)
    {
      if (node->child)
        {
          node = node->child;
          continue;
        }
      if (node->next)
        {
          node->next->prev = NULL;
          temp = node->next;
          ssh_xfree(node);
          node = temp;
        }
      else
        {
          if (node->parent)
            node->parent->child = NULL;
          temp = node->parent;
          ssh_xfree(node);
          node = temp;
        }
    }
  if (this->parent)
    {
      if (this->parent->child == this)
        {
          if (this->next)
            this->parent->child = this->next;
          if (this->prev)
            this->parent->child = this->prev;
          if (!this->prev && !this->next)
            this->parent->child = NULL;
        }
    }
  else
    {
      if (tree->root == this)
        {
          if (this->next)
            tree->root = this->next;
          if (this->prev)
            tree->root = this->prev;
          if (!this->next && !this->prev)
            tree->root = NULL;
        }
    }
  if (this->next)
    this->next->prev = this->prev;
  if (this->prev)
    this->prev->next = this->next;
  if (!this->prev && !this->next)
    if (this->parent)
      this->parent->child = NULL;
  ssh_xfree(this);
}

/* Allocate and initialize an empty tree. */
void ssh_ntree_allocate(SshNameTree *tree)
{
  SshNameTree created = ssh_xmalloc(sizeof(*created));
  created->root = NULL;
  *tree = created;
}

/* Free a tree. */
void ssh_ntree_free(SshNameTree tree)
{
  SshNameNode node = tree->root, temp;
  while (node)
    {
      temp = node->next;
      ssh_nnode_free(tree, node);
      node = temp;
    }
  ssh_xfree(tree);
}

#if 0
/* My print char routine, used for testing. */
void my_print(const char byte)
{
  printf("%c", byte);
}
#endif

/* Print tree, routine which can be used while testing. Uses given routine
   to print the tree, which should be a-ok. */
void ssh_ntree_print(SshNameTree tree,
                     void (*print_char)(const char byte))
{
  SshNameNode node = tree->root;
  size_t i;
  unsigned int flag = 0;
  
  while (node)
    {
      if (flag)
        {
          (*print_char)(',');
          flag = 0;
        }
      for (i = 0; i < node->identifier_len; i++)
        (*print_char)(node->identifier[i]);
      if (node->child)
        {
          (*print_char)('{');
          node = node->child;
          continue;
        }
      if (node->next)
        {
          flag = 1;
          node = node->next;
          continue;
        }

      while (node->parent)
        {
          node = node->parent;
          (*print_char)('}');
          flag = 1;       
          if (node->next)
            break;
        }
      if (node->next)
        {
          node = node->next;
          continue;
        }
      break;
    }
}

SshNameNode ssh_nnode_find_identifier(SshNameNode node,
                                      const char *identifier)
{
  size_t len = strlen(identifier);
  while (node)
    {
      if (node->identifier_len == len)
        {
          if (memcmp(node->identifier, identifier, len) == 0)
            {
              return node;
            }
        }
      node = node->next;
    }
  return NULL;
}

/* Get identifier out of specific node. */
char *ssh_nnode_get_identifier(SshNameNode node)
{
  char *str = ssh_xmalloc(node->identifier_len + 1);
  memcpy(str, node->identifier, node->identifier_len);
  str[node->identifier_len] = '\0';
  return str;
}

const char *ssh_nnode_get_identifier_pointer(SshNameNode node)
{
  return node->identifier;
}

/* Add a child node. */
SshNameNode ssh_ntree_add_child(SshNameTree tree, SshNameNode node,
                                const char *identifier)
{
  SshNameNode temp = ssh_nnode_allocate();

  if (tree->root == NULL)
    {
      tree->root = temp;
    }
  else
    {
      temp->parent = node;
      node->child = temp;
    }
  
  temp->identifier = identifier;
  temp->identifier_len = strlen(identifier);
  
  return temp;
}

/* Add a node to a list. */
SshNameNode ssh_ntree_add_next(SshNameTree tree, SshNameNode node,
                               const char *identifier)
{
  SshNameNode temp = ssh_nnode_allocate();

  if (tree->root == NULL)
    {
      tree->root = temp;
    }
  else
    {
      if (node->next)
        node->next->prev = temp;
      temp->next = node->next;
      temp->parent = node->parent;
      temp->prev = node;
      node->next = temp;
    }
  temp->identifier = identifier;
  temp->identifier_len = strlen(identifier);

  return temp;
}

SshNameNode ssh_nnode_get_parent(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->parent;
}

SshNameNode ssh_nnode_get_child(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->child;
}

SshNameNode ssh_nnode_get_next(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->next;
}

SshNameNode ssh_nnode_get_prev(SshNameNode node)
{
  if (node == NULL)
    return NULL;
  return node->prev;
}

SshNameNode ssh_ntree_get_root(SshNameTree tree)
{
  if (tree == NULL)
    return NULL;
  return tree->root;
}

/* Parse given namelist and get a tree out of it. Uses the tree to avoid
   code recursion. Returns SSH_NTREE_ERROR if namelist can't be parsed, or
   does not follow specifications. */
SshNameTreeStatus ssh_ntree_parse(const char *namelist, SshNameTree tree)
{
  size_t i, len, start_of_identifier;
  SshNameNode node, prev, parent;
  unsigned int flag;
#define FLAG_ID         1
#define FLAG_COMMA      2
#define FLAG_OPEN       4
#define FLAG_CLOSE      8
  int level = 0;

  if (namelist == NULL)
    return SSH_NTREE_ERROR;

  len = strlen(namelist);
  
  if (len == 0)
    return SSH_NTREE_OK;
  
  /* Initialize state variables. */
  flag = FLAG_ID;
  parent = NULL;
  prev = NULL;
  node = ssh_nnode_allocate();
  tree->root = node;
  start_of_identifier = 0;
  
  /* Run through namelist one character at a time. */
  for (i = 0; i < len; i++)
    {
      switch (namelist[i])
        {
          /* Handle identifier after comma. As always check that this is
             valid operation, and set the previous identifier length
             correctly.

             For the next node set prev field, and for the prev node set
             the next field. Set parent. Set flag for what to expect next.
             This is correct, because one gets here only if node before
             exists. 
             */

        case ',':
          if ((flag & FLAG_COMMA) != FLAG_COMMA)
            return SSH_NTREE_ERROR;
          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          prev = node;
          node = ssh_nnode_allocate();
          node->prev = prev;
          prev->next = node;
          node->parent = parent;
          flag = FLAG_ID;
          break;
          /* Handle opening parenthesis. Check that not too many levels
             are being build; which would be error. Start also a new
             list for the child node. Assume that only identifier can
             follow this mark. */
        case '{':
          if ((flag & FLAG_OPEN) != FLAG_OPEN)
            return SSH_NTREE_ERROR;

          if (++level > SSH_NTREE_MAX_LEVEL)
            return SSH_NTREE_ERROR;
          
          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          parent = node;
          node = ssh_nnode_allocate();
          node->parent = parent;
          parent->child = node;
          flag = FLAG_ID;
          break;
          /* Handle closing parenthesis. */
        case '}':
          if ((flag & FLAG_CLOSE) != FLAG_CLOSE)
            return SSH_NTREE_ERROR;
          if (!node->parent)
            return SSH_NTREE_ERROR;

          if (--level < 0)
            return SSH_NTREE_ERROR;
          
          if (node->identifier_set == 0)
            {
              node->identifier_len = i - start_of_identifier;
              node->identifier_set = 1;
            }
          node = node->parent;
          parent = node->parent;
          flag = FLAG_COMMA | FLAG_CLOSE;
          break;
          /* Handle as a default case letters of the identifier. */
        default:
          if ((flag & FLAG_ID) != FLAG_ID)
            return SSH_NTREE_ERROR;
          if (node->identifier == NULL)
            {
              node->identifier = &namelist[i];
              start_of_identifier = i;
              node->identifier_set = 0;
            }
          flag = FLAG_ID | FLAG_OPEN | FLAG_CLOSE | FLAG_COMMA;
          break;
        }
    }
  /* Unclosed parenthesis. */
  if (level)
    return SSH_NTREE_ERROR;
  
  if (node->identifier_set == 0)
    node->identifier_len = i - start_of_identifier;

#undef FLAG_ID
#undef FLAG_OPEN
#undef FLAG_CLOSE
#undef FLAG_COMMA
  
  return SSH_NTREE_OK;
}

/* Copy src tree to dest tree. Assumes dest to be empty. */
void ssh_ntree_copy(SshNameTree dest, SshNameTree src)
{
  SshNameNode src_node, dest_node, prev, parent;

  src_node = src->root;
  dest_node = NULL;
  parent = NULL;
  prev = NULL;
  while (src_node)
    {
      dest_node = ssh_nnode_allocate();
      dest_node->identifier = src_node->identifier;
      dest_node->identifier_len = src_node->identifier_len;
      dest_node->identifier_set = src_node->identifier_set;
      dest_node->parent = parent;
      dest_node->prev = prev;
      
      if (prev)
        prev->next = dest_node;
      
      if (!dest->root)
        dest->root = dest_node;

      if (parent)
        if (!parent->child)
          parent->child = dest_node;
      
      if (src_node->child)
        {
          parent = dest_node;
          src_node = src_node->child;
          prev = NULL;
          continue;
        }
      if (src_node->next)
        {
          src_node = src_node->next;
          prev = dest_node;
          continue;
        }
      dest_node = dest_node->parent;
      prev = dest_node;
      src_node = src_node->parent;
      if (src_node)
        src_node = src_node->next;
      if (dest_node)
        parent = dest_node->parent;
      else
        parent = NULL;
    }
}

/* Compute intersection between two trees. The recursive routine. */
NTreeStatus ssh_ntree_intersection_recurse(SshNameNode a,
                                           SshNameNode b,
                                           SshNameTree a_tree)
{
  SshNameNode temp, match;
  NTreeStatus status;

  while (a)
    {
      status = NTREE_OK;
      match = NULL;
      temp = b;
      while (temp)
        {
          if (a->identifier_len == temp->identifier_len)
            {
              if (memcmp(a->identifier, temp->identifier,
                         a->identifier_len) == 0)
                {
                  /* We are currently allowing the same element multiple
                     times in a list. */
                  if (match == NULL)
                    match = temp;
                }
            }
          temp = temp->next;
        }

      if (match)
        {
          if (a->child && !match->child)
            status = NTREE_REMOVE;
          if (!a->child && match->child)
            status = NTREE_REMOVE;
          if (a->child && match->child)
            status = ssh_ntree_intersection_recurse(a->child, match->child,
                                                    a_tree);
        }
                
      /* Matched? */
      if (!match)
        status = NTREE_REMOVE;

      switch (status)
        {
        case NTREE_ERROR:
          return NTREE_ERROR;
          break;
        case NTREE_REMOVE:
          temp = a->next;
          if (a->prev || a->next)
            ssh_nnode_free(a_tree, a);
          else
            return NTREE_REMOVE;
          break;
        default:
          temp = a->next;
          break;
        }
      a = temp;
    }
  return NTREE_OK;
}

/* Compute intersection between a and b. Returns intersection in ret,
   a and b unchanged. */
SshNameTreeStatus ssh_ntree_intersection(SshNameTree ret,
                                         SshNameTree a, SshNameTree b)
{
  ssh_ntree_copy(ret, a);
  
  switch (ssh_ntree_intersection_recurse(ret->root, b->root, ret))
    {
    case NTREE_OK:
      break;
    case NTREE_ERROR:
      return SSH_NTREE_ERROR;
      break;
    case NTREE_REMOVE:
      ssh_nnode_free(ret, ret->root);
      break;
    default:
      break;
    }
  return SSH_NTREE_OK;
}


/* Function expands the given tree of form:

   a{b{c{d...},d{e...}}},...

   into

   a-b-c-d,a-b-d-e,...

   */

/* This is the hard case. Using a function parse_name() which parses
   one name into a list which can then be added to the tree. However
   it is quite a lot of work in itself. */
char *ssh_ntree_transform_list_to_tree(char *namelist,
                                       SshNameNode parse_name(const char *str,
                                                              size_t len))
{
  SshNameTree tree, list;
  SshNameNode node, temp, level, tmp;
  SshDStack *stack;
  char *ret;
  
  /* We assume that the given parameter is actually a list, but then you
     never know. */
  ssh_ntree_allocate(&list);
  if (ssh_ntree_parse(namelist, list) != SSH_NTREE_OK)
    {
      ssh_ntree_free(list);
      return NULL;
    }

  node = list->root;
  level = NULL;
  stack = NULL;

  ssh_ntree_allocate(&tree);
  
  while (node)
    {
      temp = parse_name(node->identifier, node->identifier_len);

      if (temp == NULL)
        {
          ssh_ntree_free(list);
          ssh_ntree_free(tree);
          return NULL;
        }

      /* Add to the tree. */
      if (level)
        {
          tmp = level;
          while (tmp)
            {
              if (tmp->identifier_len == temp->identifier_len)
                {
                  if (memcmp(tmp->identifier, temp->identifier,
                             tmp->identifier_len) == 0)
                    {
                      /* Match found. */

                      if (tmp->child == NULL)
                        {
                          tmp->child = temp;
                          temp->parent = tmp;
                          break;
                        }

                      tmp = tmp->child;
                      temp = temp->child;
                      continue;
                    }
                }

              if (tmp->next == NULL)
                {
                  tmp->next = temp;
                  temp->prev = tmp;
                  temp->parent = tmp->parent;
                  break;
                }
              tmp = tmp->next;
            }
          /* We have now interleaved the generated name "list" into our
             tree. */
        }
      else
        {
          if (tree->root == NULL)
            tree->root = temp;
          else
            temp->parent = ssh_dstack_current(&stack); 
          level = temp;
        }
          
      if (node->child)
        {
          node = node->child;
          ssh_dstack_push(&stack, level);
          level = NULL;
          continue;
        }

      if (node->next)
        {
          node = node->next;
          continue;
        }

      while (node)
        {
          if (node->next)
            {
              node = node->next;
              break;
            }
          node = node->parent;
          level = ssh_dstack_pop(&stack);
        }
    }

  /* Make a string out of the input, this should now be correctly
     transformed. */
  ssh_ntree_generate_string(tree, &ret);

  ssh_ntree_free(tree);
  ssh_ntree_free(list);

  return ret;
}

/* This one of the transform functions is the easier,
   nothing is needed to know of the format. */

char *ssh_ntree_transform_tree_to_list(char *nametree)
{
  SshBuffer buffer;
  SshNameTree tree;
  SshNameNode node, temp;
  SshDStack *stack = NULL;
  unsigned int count;
  char *ret;
  
  ssh_ntree_allocate(&tree);
  if (ssh_ntree_parse(nametree, tree) != SSH_NTREE_OK)
    {
      ssh_ntree_free(tree);
      return NULL;
    }

  ssh_buffer_init(&buffer);
  
  node = tree->root;
    
  while (node)
    {
      if (node->child)
        {
          node = node->child;
          continue;
        }

      /* Append one full string into buffer. */

      /* First find out how long this thing actually is. */
      temp = node;
      while (temp)
        {
          ssh_dstack_push(&stack, temp);
          temp = temp->parent;
        }

      /* Then loop back using the stack. */
      count = 0;
      while (ssh_dstack_exists(&stack))
        {
          if (count > 0)
            ssh_buffer_append(&buffer, (unsigned char *) "-", 1);
          count++;
          temp = ssh_dstack_pop(&stack);
          ssh_buffer_append(&buffer, (unsigned char *) temp->identifier,
                            temp->identifier_len);
        }

      /* Move to next first. */
      if (node->next)
        {
          node = node->next;
          continue;
        }

      /* If can't move to next then try one back and to there next. */
      while (node)
        {
          if (node->next)
            {
              node = node->next;
              break;
            }
          node = node->parent;
        }

      /* Here you either have it (that is non-null node) or don't. */
    }

  /* Free the tree. */
  ssh_ntree_free(tree);
  
  /* Final touches. */
  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  ret = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
  return ret;
}

/* Return a valid namelist string. */
void ssh_ntree_generate_string(SshNameTree tree, char **namelist)
{
  SshBuffer buffer;
  SshNameNode node;
  unsigned int flag = 0;
  
  ssh_buffer_init(&buffer);
  node = tree->root;
  while (node)
    {
      if (flag)
        {
          ssh_buffer_append(&buffer, (unsigned char *) ",", 1);
          flag = 0;
        }
      ssh_buffer_append(&buffer, (unsigned char *) node->identifier,
                        node->identifier_len);
      if (node->child)
        {
          node = node->child;
          ssh_buffer_append(&buffer, (unsigned char *) "{", 1);
          continue;
        }
      if (node->next)
        {
          node = node->next;
          flag = 1;
          continue;
        }
      while (node->parent)
        {
          node = node->parent;
          ssh_buffer_append(&buffer, (unsigned char *) "}", 1);
          flag = 1;
          if (node->next)
            break;
        }
      if (node->next)
        {
          node = node->next;
          continue;
        }
      break;
    }

  ssh_buffer_append(&buffer, (unsigned char *) "\0", 1);
  *namelist = ssh_xstrdup(ssh_buffer_ptr(&buffer));
  ssh_buffer_uninit(&buffer);
}

/* Compute intersection using tree approach, which is more general, but
   takes lots of memory and time. */

char *ssh_name_list_intersection(const char *src1, const char *src2)
{
  SshNameTree a, b, c;
  char *tmp;

  /* Initialize tree's. */
  ssh_ntree_allocate(&a);
  ssh_ntree_allocate(&b);
  ssh_ntree_allocate(&c);

  /* Parse, parse, compute intersection and output suitable string. */
  if (ssh_ntree_parse(src1, a) != SSH_NTREE_OK)
    return NULL;
  if (ssh_ntree_parse(src2, b) != SSH_NTREE_OK)
    return NULL;
  if (ssh_ntree_intersection(c, a, b) != SSH_NTREE_OK)
    return NULL;
  ssh_ntree_generate_string(c, &tmp);
  
  /* Clear memory. */
  ssh_ntree_free(a);
  ssh_ntree_free(b);
  ssh_ntree_free(c);

  /* Return temporary string. */
  return tmp;
}

/* Implemented for backward compatibility. */
char *ssh_name_list_get_name(const char *namelist)
{
  SshNameTree tree;
  SshNameNode node, temp;
  char *tmp;
  
  ssh_ntree_allocate(&tree);
  if (ssh_ntree_parse(namelist, tree) != SSH_NTREE_OK)
    return NULL;
  node = ssh_ntree_get_root(tree);
  node = ssh_nnode_get_next(node);
  while (node)
    {
      temp = ssh_nnode_get_next(node);
      ssh_nnode_free(tree, node);
      node = temp;
    }
  ssh_ntree_generate_string(tree, &tmp);
  ssh_ntree_free(tree);

  return tmp;
}

const char *ssh_name_list_step_forward(const char *namelist)
{
  SshNameTree tree;
  SshNameNode node;
  const char *tmp;
  
  ssh_ntree_allocate(&tree);
  if (ssh_ntree_parse(namelist, tree) != SSH_NTREE_OK)
    return NULL;
  node = ssh_ntree_get_root(tree);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  node = ssh_nnode_get_next(node);
  if (node == NULL)
    {
      ssh_ntree_free(tree);
      return NULL;
    }
  tmp = ssh_nnode_get_identifier_pointer(node);
  ssh_ntree_free(tree);

  return tmp;
}

/* Simple ways of travelling the namelist. */

int ssh_name_list_name_len_sshproto(const char *namelist)
{
  int i;
  if (namelist == NULL)
    return 0;
  for (i = 0; namelist[i] != ',' && namelist[i] != '\0'; i++)
    ;
  return i;
}

char *ssh_name_list_get_name_sshproto(const char *namelist)
{
  int len = ssh_name_list_name_len_sshproto(namelist);
  char *name = NULL;
  
  if (len > 0)
    {
      name = ssh_xmalloc(len + 1);
      memcpy(name, namelist, len);
      name[len] = '\0';
    }
  return name;
}

const char *ssh_name_list_step_forward_sshproto(const char *namelist)
{
  int len = ssh_name_list_name_len_sshproto(namelist);

  if (len > 0)
    {
      if (namelist[len] != '\0')
        return namelist + len + 1;
    }

  return NULL;
}

char *ssh_name_list_intersection_sshproto(const char *src1, const char *src2)
{
  int total_len1, total_len2, name_len1, name_len2, max_len1, max_len2;
  Boolean prev;
  const char *tmp;
  char *dest, *dest_start;

  /* Set up the destination buffer. */
  
  prev = FALSE;
  dest = dest_start = ssh_xmalloc(strlen(src1) + 1);

  /* Start looping the two namelists. And seek for names of same length and
     only then compare. */
  
  for (total_len1 = 0, max_len1 = strlen(src1), max_len2 = strlen(src2);
       total_len1 < max_len1;)
    {
      /* Get name lenght */
      name_len1 = ssh_name_list_name_len_sshproto(src1);

      /* Start inner loop */
      for (tmp = src2, total_len2 = 0; total_len2 < max_len2; )
        {
          name_len2 = ssh_name_list_name_len_sshproto(tmp);
          
          if (name_len2 == name_len1)
            {
              if (memcmp(src1, tmp, name_len1) == 0)
                {
                  if (prev)
                    *dest++ = ',';
                  prev = TRUE;
                  memcpy(dest, src1, name_len1);
                  dest += name_len1;              
                  break;
                }
            }
          total_len2 += name_len2;

          /* Tricky part is to notice that we need to check for terminating
             zero, and quit if found. */
          tmp += name_len2;
          if (*tmp == '\0')
            break;
          /* Not zero so get past that comma. */
          tmp++;
        }
      
      total_len1 += name_len1;
      
      src1 += name_len1;
      if (*src1 == '\0')
        break;
      src1++;
    }
  /* In any case place zero terminator to the namelist. */
  *dest = '\0';
  return dest_start;
}

/* Crypto library specific routines. */

char *ssh_name_list_intersection_cipher(const char *src)
{
  char *buffer, *result;

  buffer = ssh_cipher_get_supported();
  result = ssh_name_list_intersection(src, buffer);
  ssh_xfree(buffer);
  return result;
}

char *ssh_name_list_intersection_public_key(const char *src)
{
  char *buffer, *result;

  buffer = ssh_public_key_get_supported();
  result = ssh_name_list_intersection(src, buffer);
  ssh_xfree(buffer);
  return result;
}

char *ssh_name_list_intersection_mac(const char *src)
{
  char *buffer, *result;

  buffer = ssh_mac_get_supported();
  result = ssh_name_list_intersection(src, buffer);
  ssh_xfree(buffer);
  return result;
}

char *ssh_name_list_intersection_hash(const char *src)
{
  char *buffer, *result;

  buffer = ssh_hash_get_supported();
  result = ssh_name_list_intersection(src, buffer);
  ssh_xfree(buffer);
  return result;
}

/* Compression library specific routines. */

char *ssh_name_list_intersection_compression(const char *src)
{
  char *buffer, *result;

  buffer = ssh_compress_get_supported();
  result = ssh_name_list_intersection(src, buffer);
  ssh_xfree(buffer);
  return result;
}
