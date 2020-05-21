/*

  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Sep 28 16:41:09 1996 [mkojo]
  
  Compute the section between two name lists.

  */

/*
 * $Id: namelist.h,v 1.15 1998/01/28 10:10:41 ylo Exp $
 * $Log: namelist.h,v $
 * $EndLog$
 */

#ifndef NAMELIST_H
#define NAMELIST_H

/* Attack can be launched against this system. The name tree is of form

   identifier{idenfifier{...},identifier{...},...},...

   thus having very large trees eats lots of memory while parsing them!
   Clearly some limit for maximum level of recursion allowed should be
   given. 
 */

#define SSH_NTREE_MAX_LEVEL 5

typedef enum
{
  SSH_NTREE_OK, 
  SSH_NTREE_ERROR
} SshNameTreeStatus;

/* Types for handling name trees. */
typedef struct SshNameNodeRec *SshNameNode;
typedef struct SshNameTreeRec *SshNameTree;

/* Allocation of a name tree context. */
void ssh_ntree_allocate(SshNameTree *tree);
/* How to free name tree context. */
void ssh_ntree_free(SshNameTree tree);

/* Routine for parsing a namelist (or tree) to a name tree. Tree have been
   cleared before calling this, or just allocated. Tree uses namelist for
   holding actual identifiers, thus you should NOT free namelist before
   the tree. */
SshNameTreeStatus ssh_ntree_parse(const char *namelist, SshNameTree tree);

/* Compute intersection between two name tree's. */   
SshNameTreeStatus ssh_ntree_intersection(SshNameTree ret,
					 SshNameTree a, SshNameTree b);

/* Print name tree with function that outputs single characters. */
void ssh_ntree_print(SshNameTree tree,
		     void (*print_char)(const char byte));

/* Generate valid namelist from name tree. */
void ssh_ntree_generate_string(SshNameTree tree, char **namelist);

/* Free one particular node and it's children. Tree containing it will be
   still valid, although this node will be gone forever. If given node
   does not belong to given tree, operation is undefined. */
void ssh_nnode_free(SshNameTree tree, SshNameNode node);

/* Routines for handling particular nodes. */

SshNameNode ssh_nnode_find_identifier(SshNameNode node,
				      const char *identifier);
SshNameNode ssh_ntree_add_child(SshNameTree tree, SshNameNode node,
				const char *identifier);
SshNameNode ssh_ntree_add_next(SshNameTree tree, SshNameNode node,
			       const char *identifier);
/* Get the identifier contained in a node. */
char *ssh_nnode_get_identifier(SshNameNode node);
const char *ssh_nnode_get_identifier_pointer(SshNameNode node);
/* Get nodes parent. */
SshNameNode ssh_nnode_get_parent(SshNameNode node);
/* Get nodes child. */
SshNameNode ssh_nnode_get_child(SshNameNode node);
/* Get next node in a row. */
SshNameNode ssh_nnode_get_next(SshNameNode node);
/* Get previous node in a row. */
SshNameNode ssh_nnode_get_prev(SshNameNode node);
/* Get root node from a tree. */
SshNameNode ssh_ntree_get_root(SshNameTree tree);

/* Namelist generic interface. */

/* Get the name following to 'namelist' pointer and ending with the next
   comma separator. Name string returned is zero terminated and is to
   be freed by caller with ssh_xfree.  Returns NULL if there are no more names
   or namelist is NULL. */
char *ssh_name_list_get_name(const char *namelist);

/* Step over to the next name. Returns the pointer to the next name, or NULL
   if there are no more names in the list. */
const char *ssh_name_list_step_forward(const char *namelist);

/* Step forward function that conforms SSH protocol, that is doesn't handle
   trees. */
const char *ssh_name_list_step_forward_sshproto(const char *namelist);

/* Compute the intersection between string `src1' and `src2'.
   Format for inputs and output is "name1,name2,...,namen".
   The caller must free the returned string with ssh_xfree.
   The output list will contain the names in the order in which they
   are listed in the first list. */
char *ssh_name_list_intersection(const char *src1, const char *src2);

/* This version is equivalent to the above, but cannot handle trees which
   are neccessary when talking directly to public key routines. */
char *ssh_name_list_intersection_sshproto(const char *src1, const char *src2);

/* Specialized functions for computing the intersection between `src' and
   the list of supported algorithms.  All lists are comma-separated lists
   of algorithm names.  The caller is responsible for freeing the result
   with ssh_xfree.  The output will contain the nams in the order in which
   they are listed in the argument list. */
char *ssh_name_list_intersection_cipher(const char *src);
char *ssh_name_list_intersection_mac(const char *src);
char *ssh_name_list_intersection_hash(const char *src);
char *ssh_name_list_intersection_compression(const char *src);

/* Public key routines are special case, because they implement the use of
   trees. This means that you have to prepare the input in a way that
   allows expansion to trees. Mainly the restriction is to note that {, } are
   reserved for subtree separation. */
char *ssh_name_list_intersection_public_key(const char *src);

#endif /* NAMELIST_H */
