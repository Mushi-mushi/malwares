/*
  File: sshdllist.c

  Authors: 
        Juha P‰‰j‰rvi <jpp@ssh.fi>

  Description:
        Generic doubly linked list. This implementation allows the handling
        of list nodes to speed up list manipulations in time critical
        applications.

        See the header file sshdllist.h for more complete comments.

  Copyright:
        Copyright (c) 1998 SSH Communications Security, Finland
        All rights reserved
*/

#include "sshincludes.h"
#include "sshdllist.h"

struct SshDlListNodeRec
{
  /* host_list is a pointer to the list that hosts this list node. This
     is needed to prevent the user of creating inconsistent lists by
     for example removing the current node of a list thus leaving the
     current pointer to point to a freed memory block.
     (ssh_dllist_remove_node does not take the list as an argument).

     If host_list pointer is NULL, then also previous and next pointers
     must be NULL as the node does not belong to any list and thus cannot
     have preceeding and following nodes. */
  SshDlList      host_list;

  SshDlListNode  previous;
  SshDlListNode  next;
  void          *data;
};

struct SshDlListRec
{
  /* dummy header and trailer are used to make list operations easier
     to code */
  SshDlListNode dummy_header;
  SshDlListNode dummy_trailer;

  SshDlListNode current;
};

#define FIRST_NODE(list) (list)->dummy_header->next
#define LAST_NODE(list) (list)->dummy_trailer->previous

/************* DOUBLY LINKED LIST AND LIST NODE ALLOCATION *************/

/* Allocates a new doubly linked list. */
SshDlList
ssh_dllist_allocate(void)
{
  SshDlList new_dllist = ssh_xmalloc(sizeof(struct SshDlListRec));

  new_dllist->dummy_header = ssh_xmalloc(sizeof(struct SshDlListNodeRec));
  new_dllist->dummy_trailer = ssh_xmalloc(sizeof(struct SshDlListNodeRec));

  new_dllist->dummy_header->host_list = new_dllist;
  new_dllist->dummy_header->previous = NULL;
  new_dllist->dummy_header->next = new_dllist->dummy_trailer;
  new_dllist->dummy_header->data = NULL;

  new_dllist->dummy_trailer->host_list = new_dllist;
  new_dllist->dummy_trailer->previous = new_dllist->dummy_header;
  new_dllist->dummy_trailer->next = NULL;
  new_dllist->dummy_trailer->data = NULL;

  new_dllist->current = FIRST_NODE(new_dllist);

  return new_dllist;
}

/* Frees the given doubly linked list. */
void
ssh_dllist_free(SshDlList list)
{
  ssh_dllist_clear(list);

  ssh_xfree(list->dummy_header);
  ssh_xfree(list->dummy_trailer);
  ssh_xfree(list);
}

/* Allocates a new doubly linked list node. */
SshDlListNode
ssh_dllist_node_allocate(void)
{
  SshDlListNode new_dllist_node = ssh_xmalloc(sizeof(struct SshDlListNodeRec));

  new_dllist_node->host_list = NULL;
  new_dllist_node->previous = NULL;
  new_dllist_node->next = NULL;
  new_dllist_node->data = NULL;

  return new_dllist_node;
}

/* Frees the given doubly linked list node. */
void
ssh_dllist_node_free(SshDlListNode node)
{
  if (node->host_list != NULL)
    {
      /* NOTE: 'node' cannot be dummy_header or dummy_trailer, because
         the user has no way of getting a pointer to either of these,
         and thus 'node' does not have to be tested. */
      node->previous->next = node->next;
      node->next->previous = node->previous;

      if (node->host_list->current == node)
        node->host_list->current = node->next;
    }

  ssh_xfree(node);
}

/**************************** NODE HANDLING ****************************/

/* Gets the data item carried by the given list node. */
void *
ssh_dllist_node_get_item(SshDlListNode node)
{
  return node->data;
}

/* Sets the data item carried by the given list node. */
void
ssh_dllist_node_set_item(SshDlListNode node, void *item)
{
  node->data = item;
}

/* Gets the previous node to the given node. */
SshDlListNode
ssh_dllist_node_get_previous(SshDlListNode node)
{
  if (node->previous == node->host_list->dummy_header)
    return NULL;

  return node->previous;
}

/* Gets the node next after the given node. */
SshDlListNode
ssh_dllist_node_get_next(SshDlListNode node)
{
  if (node->next == node->host_list->dummy_trailer)
    return NULL;

  return node->next;
}

/********************** LIST AND NODE MANIPULATION *********************/

/* Adds an item to a doubly linked list. */
SshDlListError
ssh_dllist_add_item(SshDlList list, void *item,
                    SshDlListPosition position)
{
  /* Allocate a list node for the data item. */
  SshDlListNode new_node = ssh_xmalloc(sizeof(struct SshDlListNodeRec));

  new_node->host_list = list;
  new_node->data = item;

  /* Place the new node to the list. */
  switch (position)
    {
    case SSH_DLLIST_BEGIN:
      list->dummy_header->next->previous = new_node;
      new_node->next = list->dummy_header->next;
      list->dummy_header->next = new_node;
      new_node->previous = list->dummy_header;
      break;

    case SSH_DLLIST_END:
      list->dummy_trailer->previous->next = new_node;
      new_node->previous = list->dummy_trailer->previous;
      list->dummy_trailer->previous = new_node;
      new_node->next = list->dummy_trailer;
      break;

    case SSH_DLLIST_CURRENT:
      list->current->previous->next = new_node;
      new_node->previous = list->current->previous;
      list->current->previous = new_node;
      new_node->next = list->current;
      break;

    default:
      ssh_xfree(new_node);
      return SSH_DLLIST_ERROR;
    }

  return SSH_DLLIST_OK;
}

/* Adds a node to a doubly linked list. */
SshDlListError
ssh_dllist_add_node(SshDlList list, SshDlListNode node,
                    SshDlListPosition position)
{
  /* Check that the node is not used by another list */
  if (node->host_list != NULL)
    return SSH_DLLIST_NODE_RESERVED;

  node->host_list = list;

  /* Place the new node to the list. */
  switch (position)
    {
    case SSH_DLLIST_BEGIN:
      list->dummy_header->next->previous = node;
      node->next = list->dummy_header->next;
      list->dummy_header->next = node;
      node->previous = list->dummy_header;
      break;

    case SSH_DLLIST_END:
      list->dummy_trailer->previous->next = node;
      node->previous = list->dummy_trailer->previous;
      list->dummy_trailer->previous = node;
      node->next = list->dummy_trailer;
      break;

    case SSH_DLLIST_CURRENT:
      list->current->previous->next = node;
      node->previous = list->current->previous;
      list->current->previous = node;
      node->next = list->current;
      break;

    default:
      return SSH_DLLIST_ERROR;
    }

  return SSH_DLLIST_OK;
}

/* Adds a node to a doubly linked list before a given node (that is already
   on the list). */
SshDlListError
ssh_dllist_add_node_at(SshDlList list, SshDlListNode node,
                       SshDlListNode position)
{
  if (position->host_list != list)
    return SSH_DLLIST_ERROR;

  if (node->host_list != NULL)
    return SSH_DLLIST_NODE_RESERVED;

  node->host_list = list;
  position->previous->next = node;
  node->previous = position->previous;
  position->previous = node;
  node->next = position;

  return SSH_DLLIST_OK;
}

/* Deletes the current node/item and returns the item removed from the
   list. */
void *
ssh_dllist_delete_current(SshDlList list)
{
  SshDlListNode current = list->current;
  void *item = list->current->data;

  if (current == list->dummy_header ||
      current == list->dummy_trailer)
    return NULL;

  current->previous->next = current->next;
  current->next->previous = current->previous;
  list->current = current->next;

  ssh_xfree(current);
  return item;
}

/* Removes the current node from the list without freeing it and returns
   pointer to it. */
SshDlListNode
ssh_dllist_remove_current_node(SshDlList list)
{
  SshDlListNode current = list->current;

  if (current == list->dummy_header ||
      current == list->dummy_trailer)
    return NULL;

  current->previous->next = current->next;
  current->next->previous = current->previous;
  list->current = current->next;

  /* As it was defined (in the definition of struct SshDlListNodeRec), if
     host_list of a node is NULL then its previous and next pointer must
     also be NULL. */
  current->host_list = NULL;
  current->previous = NULL;
  current->next = NULL;

  return current;
}

/* Mapper function that decides wheater a given list item must be deleted
   or not. This is needed in the function ssh_dllist_delete_item for the
   mapcar call to delete list items. */
static void *delete_item_mapper(void *item, void *item_to_delete)
{
  if (item == item_to_delete)
    return NULL;

  return item;
}

/* Deletes an item from the list. */
void
ssh_dllist_delete_item(SshDlList list, void *item)
{
  while (list->current->data == item &&
         list->current != list->dummy_trailer)
    list->current = list->current->next;

  ssh_dllist_mapcar(list, delete_item_mapper, item);
}

/* Deletes a list node regardless wheather it is on the list or not. */
void
ssh_dllist_delete_node(SshDlListNode node)
{
  if (node->host_list != NULL)
    {
      /* NOTE: 'node' cannot be dummy_header or dummy_trailer, because
         the user has no way of getting a pointer to either of these,
         and thus 'node' does not have to be tested. */
      node->previous->next = node->next;
      node->next->previous = node->previous;

      if (node->host_list->current == node)
        node->host_list->current = node->next;
    }

  ssh_xfree(node);
}

/* Removes a list node without freeing it. */
void
ssh_dllist_remove_node(SshDlListNode node)
{
  if (node->host_list != NULL)
    {
      /* NOTE: 'node' cannot be dummy_header or dummy_trailer, because
         the user has no way of getting a pointer to either of these,
         and thus 'node' does not have to be tested. */
      node->previous->next = node->next;
      node->next->previous = node->previous;

      if (node->host_list->current == node)
        node->host_list->current = node->next;
    }

  /* As it was defined (in the definition of struct SshDlListNodeRec), if
     host_list of a node is NULL then its previous and next pointer must
     also be NULL. */
  node->host_list = NULL;
  node->previous = NULL;
  node->next = NULL;
}

/* A mapper that returns NULL regardless of the data item passed to it.
   The result is that the whole list is cleared. */
static void *dllist_clear_mapper(void *item, void *ctx)
{
  return NULL;
}

/* Clears the given list. */
void
ssh_dllist_clear(SshDlList list)
{
  ssh_dllist_mapcar(list, dllist_clear_mapper, NULL);
}

/**************************** LIST SEARCHING ***************************/

/* Move current pointer of the list to the first item/node in the list. */
void
ssh_dllist_rewind(SshDlList list)
{
  list->current = FIRST_NODE(list);
}

/* Move current pointer of the list to the last item/node in the list. */
void
ssh_dllist_end(SshDlList list)
{
  list->current = LAST_NODE(list);
}

/* Move the current pointer of the list n items/nodes forwards. */
SshDlListError
ssh_dllist_fw(SshDlList list, int n)
{
  SshDlListNode current = list->current;

  while (n > 0 && current != list->dummy_trailer)
    {
      current = current->next;
      n--;
    }
  list->current = current;

  if (current != list->dummy_trailer)
    return SSH_DLLIST_OK;
  else
    return SSH_DLLIST_ERROR;
}

/* Move the current pointer of the list n items/nodes backwards. */
SshDlListError
ssh_dllist_bw(SshDlList list, int n)
{
  SshDlListNode current = list->current;

  while (n > 0 && current != list->dummy_header)
    {
      current = current->previous;
      n--;
    }
  list->current = current;

  if (current != list->dummy_header)
    return SSH_DLLIST_OK;
  else
    return SSH_DLLIST_ERROR;
}

/* Search the list for an item. */
SshDlListError
ssh_dllist_find(SshDlList list, void *item)
{
  SshDlListNode current = FIRST_NODE(list);

  while (current->data != item && current != list->dummy_trailer)
    {
      current = current->next;
    }

  if (current == list->dummy_trailer)
    return SSH_DLLIST_ERROR;

  list->current = current;
  return SSH_DLLIST_OK;
}

/* Returns the pointer to the current item. */
void *
ssh_dllist_current(SshDlList list)
{
  /* list->dummy_{header,trailer} have NULL data pointer, so
     list->current does not need to be checked. */
  return list->current->data;
}

/* Returns the pointer to the current node. */
SshDlListNode
ssh_dllist_current_node(SshDlList list)
{
  if (list->current == list->dummy_header ||
      list->current == list->dummy_trailer)
    return NULL;

  return list->current;
}

/************************ LIST STATE INFORMATION ***********************/

/* Returns the number of items stored in the doubly linked list. */
int
ssh_dllist_length(SshDlList list)
{
  SshDlListNode current = FIRST_NODE(list);
  int count;

  for (count=0; current != list->dummy_trailer; count++)
    current = current->next;

  return count;
}

/* Tests if the list is empty or not. */
Boolean
ssh_dllist_is_empty(SshDlList list)
{
  if (list->dummy_header->next == list->dummy_trailer)
    return TRUE;
  else
    return FALSE;
}

/* Tests if the current pointer points to a valid list item. */
Boolean
ssh_dllist_is_current_valid(SshDlList list)
{
  if (list->current != list->dummy_header &&
      list->current != list->dummy_trailer)
    return TRUE;
  else
    return FALSE;
}

/************************** ADVANCED FEATURES **************************/

/* Traverses the list with a mapper function. */
void
ssh_dllist_mapcar(SshDlList list, SshDlListMapCarFunc mapcar_func,
                  void *ctx)
{
  SshDlListNode current = FIRST_NODE(list);
  SshDlListNode next_node;
  void *returned_item;

  while (current != list->dummy_trailer)
    {
      returned_item = (*mapcar_func)(current->data, ctx);

      next_node = current->next;
      if (returned_item == NULL)
        ssh_dllist_delete_node(current);
      else if (returned_item != current->data)
        current->data = returned_item;

      current = next_node;
    }
}
