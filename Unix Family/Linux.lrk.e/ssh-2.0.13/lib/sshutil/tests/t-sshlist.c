/*

  t-sshlist.c
  
  Author: Vesa Suontama <vsuontam@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Aug 18 23:00:00 1998 [vsuontam]

  A very simple sshlist test.
  */

#include "sshincludes.h"
#include "sshlist.h"


int *k1, *k2, *k3, *k4, *k5;
 

void *my_mapcar_test(void *data, void *ctx)
{
  if (ctx == data)
  {
    assert(data == &k2);
  }
  return data;
}


void *drop_ctx_test(void *data, void *ctx)
{
  if (ctx == data)
  {
    return NULL;
  }
  return data;
}


void *changex5(void *data, void *ctx)
{
  if (ctx == data)
  {
    return &k5;
  }
  return data;
}

int main()
{
  
  SshList list;
  int i, amount;
  list = ssh_list_allocate();
  
  /* Add and find tests*/
  printf("Length 0 test.\n");
  assert( ssh_list_length(list) == 0);
  printf("Adding stuff to the list\n");
  assert( ssh_list_length(list) == 0);
  assert(ssh_list_add(list, &k1) == 1);
  assert(ssh_list_add(list, &k2) == 2);
  assert( ssh_list_add(list, &k3) == 3);
  assert( ssh_list_add(list, &k4) == 4);
  assert( ssh_list_find(list, &k1) == 1);
  assert( ssh_list_find(list, &k2) == 2);
  assert( ssh_list_find(list, &k3) == 3);
  assert( ssh_list_find(list, &k5) == 0);
  assert( ssh_list_find(list, &k1) == 1);
  assert( ssh_list_length(list) == 4);
  
  /* testing mapcar*/
  printf("MapCar Test.\n");
  ssh_list_mapcar(list, my_mapcar_test, &k2);
  
  /* Dropping items with mapcar*/
  printf("Drop List tests.\n");
  ssh_list_mapcar(list, drop_ctx_test, &k2);
  assert( ssh_list_find(list, &k2) == 0);
  assert( ssh_list_length(list) == 3);

  /* Changing items with mapcar*/
  printf("Change item with mapcar tests.\n");
  ssh_list_mapcar(list, changex5, &k4);
  assert( ssh_list_find(list, &k4) == 0);
  assert( ssh_list_find(list, &k5) > 0);
  

  ssh_list_mapcar(list, drop_ctx_test, &k1);
  assert( ssh_list_find(list, &k1) == 0);
  assert( ssh_list_length(list) == 2);
  ssh_list_mapcar(list, drop_ctx_test, &k3);
  assert( ssh_list_find(list, &k3) == 0);
  assert( ssh_list_length(list) == 1);
  ssh_list_mapcar(list, drop_ctx_test, &k4);
  assert( ssh_list_find(list, &k4) == 0);
  assert( ssh_list_length(list) == 1);
  
  /* Adding stuff again */
  printf("Adding stuff to the list again.\n");
  assert(ssh_list_add(list, &k1) == 2);
  assert(ssh_list_add(list, &k2) == 3);
  assert( ssh_list_add(list, &k3) == 4);
  assert( ssh_list_add(list, &k4) == 5);

  /* Deleting stuff with delete function*/
  printf("Deleting stuff from the list again but with a delete function\n");
  ssh_list_delete(list, &k1);
  assert( ssh_list_length(list) == 4);
  ssh_list_delete(list, &k1);
  assert( ssh_list_length(list) == 4);
  
  /* Adding a lot */
  printf("Adding 1000 items to the list\n");
  for (i=0;i<1000;i++)
    ssh_list_add(list, (void*)&k1);
  assert((amount = ssh_list_length(list)) > 1000);
  i=0;

  /* Traversing the list*/
  printf("Traversing the whole list forward...\n");
  for (ssh_list_rewind(list); ssh_list_current_valid(list);ssh_list_fw(list,1))
    i++;
  assert(i == amount);

  i=0;
  printf("Traversing the whole list backward...\n");
  for (ssh_list_end(list); ssh_list_current_valid(list);ssh_list_bw(list,1))
    i++;
  assert(i == amount);


  ssh_list_free(list);
  printf("List test OK.\n");
  return 0;
}

