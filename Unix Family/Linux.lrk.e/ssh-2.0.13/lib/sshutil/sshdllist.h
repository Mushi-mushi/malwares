/*
  File: sshdllist.h

  Authors:
        Juha P‰‰j‰rvi <jpp@ssh.fi>

  Description:
        Generic doubly linked list. This implementation allows the
        handling of list nodes to speed up list manipulations and
        especially reordering of lists. (The speed gain is due to the
        absence of memory allocations/deallocations if nodes are moved
        around the list or between lists).

        This list behaves as a conventional doubly linked list if the
        following subset of functions is used:
         - ssh_dllist_allocate
         - ssh_dllist_free
         - ssh_dllist_add_item
         - ssh_dllist_delete_current
         - ssh_dllist_delete_item
         - ssh_dllist_clear
         - ssh_dllist_rewind
         - ssh_dllist_end
         - ssh_dllist_fw
         - ssh_dllist_bw
         - ssh_dllist_find
         - ssh_dllist_current
         - ssh_dllist_length
         - ssh_dllist_is_empty
         - ssh_dllist_is_current_valid
         - ssh_dllist_mapcar

        The additional node handling functions are:
         - ssh_dllist_node_allocate
         - ssh_dllist_node_free
         - ssh_dllist_node_get_item
         - ssh_dllist_node_set_item
         - ssh_dllist_node_get_previous
         - ssh_dllist_node_get_next
         - ssh_dllist_add_node
         - ssh_dllist_add_node_at
         - ssh_dllist_remove_current_node
         - ssh_dllist_delete_node
         - ssh_dllist_remove_node
         - ssh_dllist_current_node

        The handling of list nodes also makes it possible to make a sort
        of classified lists. The user can for example keep pointers to the
        list nodes after which all the list elements have a certain
        property. For example from some point on the list elements could
        have property A and from some later point on the list elements
        would have property B that is stricter than property A, and from
        some even later point on... and so on. The list could then be
        reordered all the time according to the (possibly changing)
        properties of the list elements. All this can be done in O(1)
        time and with no memory allocations or deallocations (unless
        there are really new nodes added to the list).

        The function call interface is partly base on SshList written by
        Vesa Suontama.

  Terminology:
        The API of this list may seem a bit different from the API of
        a conventional list abstraction. This is because this
        implementation exposes a part of the internal structure of the
        list to the programmer, namely the list nodes. The following
        explains the data types in this implementation:

        SshDlList
           The data type for the doubly linked list.

        SshDlListNode
           The data type for list nodes. The list consists of list nodes
           that are chained together to form the list. List nodes can be
           thought of consisting pointers to the previous and next nodes
           of the list and a pointer to the data carried by the node. The
           implication of this is that there is one list node for each
           data item in the list.

  Constraints:
        It is expected that the pointers to lists and nodes given as
        arguments to the SshDlList API functions are valid. In other
        words, no testing is done to confirm the validity of pointers.
        Thus invalid pointer given as an argument to any of the functions
        is likely to cause a segmentation violation.

        When a new doubly linked list is created its current item/node
        pointer (later current pointer) is invalid, that is it does not
        point to any item in the list (naturally, there are no items in
        a new list). The current pointer also stays invalid even if items
        are added to the list. It will not become valid until the first
        ssh_dllist_rewind or ssh_dllist_end call is made.

  Copyright:
        Copyright (c) 1998 SSH Communications Security, Finland
        All rights reserved
*/

#ifndef SSHDLLIST_H
#define SSHDLLIST_H

/* The data type for the doubly linked list */
typedef struct SshDlListRec *SshDlList;

/* The data type for the doubly linked list nodes */
typedef struct SshDlListNodeRec *SshDlListNode;

/* Possible positions for list manipulation */
typedef enum {
  SSH_DLLIST_BEGIN,
  SSH_DLLIST_END,
  SSH_DLLIST_CURRENT
} SshDlListPosition;

/* Error codes for SshDlList */
typedef enum {
  SSH_DLLIST_OK,                /* success */
  SSH_DLLIST_ERROR,             /* generic error code */
  SSH_DLLIST_NODE_RESERVED      /* node reserved for another list */
} SshDlListError;

/************* DOUBLY LINKED LIST AND LIST NODE ALLOCATION *************/

/* Allocates a new doubly linked list.

   Returns:
     The newly created SshDlList object.
*/
SshDlList
ssh_dllist_allocate(void);

/* Frees the given doubly linked list.

   Parameters:
     list       the doubly linked list to be freed
*/
void
ssh_dllist_free(SshDlList list);

/* Allocates a new doubly linked list node. Nodes need not to be allocated
   unless it is desired by the user for some reason; adding an item to
   the list automatically allocates a node for the item. In other words
   this fuction is here just for convinience.

   Returns:
     The newly created SshDlListNode object.
*/
SshDlListNode
ssh_dllist_node_allocate(void);

/* Frees the given doubly linked list node. Note that if the node is
   currently a member of some doubly linked list, the node (and the
   item it carries) is removed from the list.

   Parameters:
     node       the doubly linked list node to be freed
*/
void
ssh_dllist_node_free(SshDlListNode node);

/**************************** NODE HANDLING ****************************/

/* Gets the data item carried by the given list node.

   Complexity: O(1)
   Parameters:
     node       the node
   Returns:
     The data item carried by the node.
*/
void *
ssh_dllist_node_get_item(SshDlListNode node);

/* Sets the data item carried by the given list node.

   Complexity: O(1)
   Parameters:
     node       the node
     item       the item to be carried by the node
*/
void
ssh_dllist_node_set_item(SshDlListNode node, void *item);

/* Gets the previous node to the given node. If the given node is the
   first node of the list, NULL is returned.

   Complexity: O(1)
   Parameters:
     node       the node
   Returns:
     The node preceeding the node given as an argument or NULL if the
     node is the first node of the list.
 */
SshDlListNode
ssh_dllist_node_get_previous(SshDlListNode node);

/* Gets the node next after the given node. If the given node is the
   last node of the list, NULL is returned.

   Complexity: O(1)
   Parameters:
     node       the node
   Returns:
     The node after the node given as an argument or NULL if the node is
     the last node of the list.
 */
SshDlListNode
ssh_dllist_node_get_next(SshDlListNode node);

/********************** LIST AND NODE MANIPULATION *********************/

/* Adds an item to a doubly linked list. Note that this function also adds
   a list node to the list to hold the item.

   It must be defined, where the item is put in the list: to the beginning
   or to the end of the list or before the item/node pointed by the
   current pointer of the list. If the item is put before the current
   item/node, the current pointer remains the same.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
     item       the item to be added
     position   position where the item is added to the list
   Returns:
     SSH_DLLIST_OK      on success
     SSH_DLLIST_ERROR   if position has an invalid value
*/
SshDlListError
ssh_dllist_add_item(SshDlList list, void *item, SshDlListPosition position);

/* Adds a node to a doubly linked list. Note that the node must have been
   allocated before a call to this function i.e. the node must be a valid
   one.

   It must be defined, where the item is put in the list: to the beginning
   or to the end of the list or before the item/node pointed by the
   current pointer of the list. If the item is put before the current
   item/node, the current pointer remains the same.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
     node       the node to be added
     position   position where the node is added to the list
   Returns:
     SSH_DLLIST_OK              on success
     SSH_DLLIST_ERROR           if position has an invalid value
     SSH_DLLIST_NODE_RESERVED   if the node being added is owned by
                                another list
*/
SshDlListError
ssh_dllist_add_node(SshDlList list, SshDlListNode node,
                    SshDlListPosition position);

/* Adds a node to a doubly linked list before a given node (that is already
   on the list).

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
     node       the node to be added
     position   the node before which the new node is added
   Returns:
     SSH_DLLIST_OK              on success
     SSH_DLLIST_ERROR           if the node before which the new node is
                                to be added (position) is not a member of
                                the list
     SSH_DLLIST_NODE_RESERVED   if the node being added is owned by
                                another list
*/
SshDlListError
ssh_dllist_add_node_at(SshDlList list, SshDlListNode node,
                       SshDlListNode position);

/* Deletes the current item/node (current node is freed) and returns the
   item removed from the list. The item itself is not freed. If the
   current pointer of the list is not valid, NULL is returned. Note that
   it is legal to store NULL pointers in to the list, so users should
   know wheather the returned NULL results from NULL list item or current
   pointer being invalid (see ssh_dllist_is_current_valid).

   Current pointer of the list will be moved to point the next item/node
   in the list. If deleted item/node was the last item/node of the list,
   the current pointer becomes invalid.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     The removed item or NULL if current pointer is not valid.
 */
void *
ssh_dllist_delete_current(SshDlList list);

/* Removes the current node from the list without freeing it and returns
   pointer to it. If the current pointer of the list is not valid, NULL
   is returned.

   Current pointer of the list will be moved to point the next item/node
   in the list. If removed node was the last node of the list, the
   current pointer becomes invalid.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     Pointer to the removed node or NULL if the current pointer of the
     list is not valid.
 */
SshDlListNode
ssh_dllist_remove_current_node(SshDlList list);

/* Deletes an item from the list. Every occurence of the given item is
   deleted from the list and the corresponding nodes are also deleted
   (i.e. the nodes are freed). The item itself is not freed.

   If the current pointer of the list points to the item that is to be
   removed, it will be moved to point the next item that is different
   from the removed item.

   Complexity: O(n)
   Parameters:
     list       the doubly linked list
     item       the item to be deleted
*/
void
ssh_dllist_delete_item(SshDlList list, void *item);

/* Deletes a list node regardless wheather it is on the list or not. This
   has exactly the same effect as freeing a node. The data item possibly
   carried by the node is not freed.

   If the node to be deleted is the node pointed by current pointer of
   the list, the current pointer will be moved to point the node/item
   next after the deleted node. If the deleted node was the last node of
   the list, current pointer of the list will become invalid.

   Complexity: O(1)
   Parameters:
     node       the doubly linked list node to be freed
*/
void
ssh_dllist_delete_node(SshDlListNode node);

/* Removes a list node without freeing it. The list node is removed from
   the list, but it is not freed, and thus it can be added to the list
   again to any position or to different list.

   If the node to be removed is the node pointed by current pointer of
   the list, the current pointer will be moved to point the node/item
   next after the removed node. If the removed node was the last node of
   the list, current pointer of the list will become invalid.

   Complexity: O(1)
   Parameters:
     node       the doubly linked list node to be removed
*/
void
ssh_dllist_remove_node(SshDlListNode node);

/* Clears the given list. All the items are dropped from the list and all
   the associated list nodes are freed. The data items are not freed.
   Care must be taken that the data items are not lost after the call to
   this function.

   Complexity: O(n)
   Parameters:
     list       the doubly linked list to be cleared
*/
void
ssh_dllist_clear(SshDlList list);

/**************************** LIST SEARCHING ***************************/

/* Move current pointer of the list to the first item/node in the list.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
*/
void
ssh_dllist_rewind(SshDlList list);

/* Move current pointer of the list to the last item/node in the list.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
*/
void
ssh_dllist_end(SshDlList list);

/* Move the current pointer of the list n items/nodes forwards. If the
   current pointer of the list is not valid, the behaviour of this
   function is not defined.

   Complexity: O(n) (where n is the number of steps)
   Parameters:
     list       the doubly linked list
     n          number of steps to go forwards
   Returns:
     SSH_DLLIST_OK      on success
     SSH_DLLIST_ERROR   uppon failure to go n steps forwards
*/
SshDlListError
ssh_dllist_fw(SshDlList list, int n);

/* Move the current pointer of the list n items/nodes backwards. If the
   current pointer of the list is not valid, the behaviour of this
   function is not defined.

   Complexity: O(n) (where n is the number of steps)
   Parameters:
     list       the doubly linked list
     n          number of steps to go backwards
   Returns:
     SSH_DLLIST_OK      on success
     SSH_DLLIST_ERROR   uppon failure to go n steps backwards
*/
SshDlListError
ssh_dllist_bw(SshDlList list, int n);

/* Search the list for an item and sets the current pointer of the list
   to the first occurence of the item.

   Complexity: O(n)
   Parameters:
     list       the doubly linked list
     item       the item to be searched
   Returns:
     SSH_DLLIST_OK      on success
     SSH_DLLIST_ERROR   if the item was not found
*/
SshDlListError
ssh_dllist_find(SshDlList list, void *item);

/* Returns the pointer to the current item.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     The current item or NULL if the list is empty or current pointer is
     not valid.
 */
void *
ssh_dllist_current(SshDlList list);

/* Returns the pointer to the current node.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     The current node or NULL if the list is empty or the current pointer
     is not valid.
 */
SshDlListNode
ssh_dllist_current_node(SshDlList list);

/************************ LIST STATE INFORMATION ***********************/

/* Returns the number of items stored in the doubly linked list.

   Complexity: O(n)
   Parameters:
     list       the doubly linked list
   Returns:
     The number of items in the list.
*/
int
ssh_dllist_length(SshDlList list);

/* Tests if the list is empty or not.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     TRUE if the list is empty or FALSE if it has items.
*/
Boolean
ssh_dllist_is_empty(SshDlList list);

/* Tests if the current pointer points to a valid list item.

   Complexity: O(1)
   Parameters:
     list       the doubly linked list
   Returns:
     TRUE if current pointer points to a valid list item, otherwise
     FALSE.
 */
Boolean
ssh_dllist_is_current_valid(SshDlList list);

/************************** ADVANCED FEATURES **************************/

/* A map car function pointer template. See ssh_dllist_mapcar below */
typedef void *(*SshDlListMapCarFunc)(void *item, void *ctx);

/* Traverses the list with a mapper function. Mapper function is called
   with each item in the list with user given context pointer. If mapper
   function returns NULL, the item in question is dropped from the list
   (and the associated list node is freed). If mapper function returns
   the item itself, the item is left as it is. If mapper function returns
   other non-NULL pointer, the current item is dropped and replaced by
   this returned new item (the list node is preserved, only the data item
   it carries is replaced).

   Note: if an item is dropped by the mapper function, the library has no
   more references to it and it is lost. So, care must be taken to ensure
   that no items are lost and thus not freed (causing a memory leak).

   Complexity: O(n) (of course, this does not include the complexity of
                     the mapper function as it varies by the function)
   Parameters:
     list        the doubly linked list
     mapcar_func the mapper function
     ctx         the context pointer to be given to the mapper function
*/
void
ssh_dllist_mapcar(SshDlList list, SshDlListMapCarFunc mapcar_func,
                  void *ctx);

#endif /* SSHDLLIST_H */
