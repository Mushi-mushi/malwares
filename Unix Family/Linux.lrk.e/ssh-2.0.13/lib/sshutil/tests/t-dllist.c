/*
  File: t-dllist.h

  Authors:
        Juha P‰‰j‰rvi <jpp@ssh.fi>

  Description:
        Test driver for doubly linked list implemented in sshdllist.[hc].

  Copyright:
        Copyright (c) 1998 SSH Communications Security, Finland
        All rights reserved
*/

#include "sshincludes.h"
#include "sshdllist.h"
#include "sshtimemeasure.h"

#define TEST_NUMBERS 20
#define ITEMS_TO_ADD_TO_THE_LIST 50000

/* Test data object */
typedef struct TestDataRec
{
  int number;
} TestData;

TestData *test_data;

/* Mapper to print out the contents of single list element. Used by
   print_list. */
void *print_list_mapper(void *item, void *ctx)
{
  printf("%d, ", ((TestData *)item)->number);
  return item;
}

/* Prints out the list contents. */
void print_list(SshDlList list)
{
  printf("List contents:\n");
  ssh_dllist_mapcar(list, print_list_mapper, NULL);
  printf("\n\n");
}

/* Reverses the list. */
void reverse_list(SshDlList list)
{
  SshDlListNode node;

  ssh_dllist_rewind(list);
  while (ssh_dllist_is_current_valid(list))
    {
      node = ssh_dllist_remove_current_node(list);
      ssh_dllist_add_node(list, node, SSH_DLLIST_BEGIN);
    }
}

/* Mapper for removing even items from a list. */
void *remove_evens(void *item, void *ctx)
{
  if (((TestData *)item)->number % 2 == 0)
    return NULL;
  else
    return item;
}

/* The main test program. */
int main(int argc, char *argv[])
{
  Boolean verbose = FALSE;
  SshDlList t_list;
  SshTimeMeasure ssh_timer;
  double timer_value;
  int i, k, evens, odds;

  /* Initialize the random number generator and timer */
  srand((unsigned int)ssh_time());
  ssh_timer = ssh_time_measure_allocate();

  printf("Running test for SshDlList");

  /* Check for verbose output option */
  if (argc == 2 && !strcmp("-v", argv[1]))
    {
      verbose = TRUE;
      printf(".\n\n");
    }
  else
    printf(", use -v for verbose output.\n");

  /* Initialize the test data */
  test_data = ssh_xmalloc(TEST_NUMBERS * sizeof(TestData));
  for (i=0; i < TEST_NUMBERS; i++)
    test_data[i].number = i;

  t_list = ssh_dllist_allocate();

  /* List addition tests */
  for (i=TEST_NUMBERS/2; i < TEST_NUMBERS; i++)
    if (ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_END)
        != SSH_DLLIST_OK)
      ssh_fatal("t-dllist: list addition failed. Test failed.");

  if (verbose)
    print_list(t_list);

  for (i=TEST_NUMBERS/2-1; i >= 0; i--)
    if (ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_BEGIN)
        != SSH_DLLIST_OK)
      ssh_fatal("t-dllist: list addition failed. Test failed.");

  if (verbose)
    print_list(t_list);

  /* List searching tests */
  if (verbose)
    printf("Testing list searching... ");
  ssh_dllist_rewind(t_list);

  i = 5;
  ssh_dllist_fw(t_list, i);
  if (ssh_dllist_current(t_list) != &test_data[i])
    ssh_fatal("t-dllist: problems with ssh_dllist_fw. Test failed.");

  i = 11;
  ssh_dllist_find(t_list, &test_data[i]);
  if (ssh_dllist_current(t_list) != &test_data[i])
    ssh_fatal("t-dllist: problems with ssh_dllist_find. Test failed.");

  if (verbose)
    printf("OK\n");

  /* List clear test */
  if (verbose)
    printf("Clearing the list... ");
  ssh_dllist_clear(t_list);
  if (verbose)
    printf("checking is the list empty... ");
  if (ssh_dllist_is_empty(t_list) != TRUE)
    ssh_fatal("t-dllist: list NOT empty! Test failed.\n");
  else if (verbose)
    printf("OK\n");

  /* ----------------------- performance testing ----------------------- */

  /* list addition */
  evens = odds = 0;
  ssh_time_measure_start(ssh_timer);
  for (k=0; k < ITEMS_TO_ADD_TO_THE_LIST; k++)
    {
      i = (int)((rand() / 256) % TEST_NUMBERS);

      if (i < 0 || i >= TEST_NUMBERS)
        ssh_fatal("t-dllist: random number calculation produced index out "
                  "of range.");

      if (i % 2 == 0)
        evens++;
      else
        odds++;

      ssh_dllist_add_item(t_list, (void *)&test_data[i], SSH_DLLIST_END);
    }
  ssh_time_measure_stop(ssh_timer);
  timer_value = (double)ssh_time_measure_get(ssh_timer,
                                             SSH_TIME_GRANULARITY_SECOND);
  if (verbose)
    printf("%d item additions took %.2f ms. Added %d evens, %d odds.\n",
           ITEMS_TO_ADD_TO_THE_LIST, timer_value * 1000, evens, odds);
  if (evens + odds != ITEMS_TO_ADD_TO_THE_LIST)
    ssh_fatal("t-dllist: evens + odds does not match. Test failed.");

  /* list length calculation */
  ssh_time_measure_reset(ssh_timer);
  ssh_time_measure_start(ssh_timer);
  i = ssh_dllist_length(t_list);
  ssh_time_measure_stop(ssh_timer);
  timer_value = (double)ssh_time_measure_get(ssh_timer,
                                             SSH_TIME_GRANULARITY_SECOND);
  if (verbose)
    printf("Calculating list length took %.2f ms for %d elements.\n",
           timer_value * 1000, i);
  if (i != ITEMS_TO_ADD_TO_THE_LIST)
    ssh_fatal("t-dllist: number of list elements does not match the expected. Test failed.");

  /* list reverse */
  ssh_time_measure_reset(ssh_timer);
  ssh_time_measure_start(ssh_timer);
  reverse_list(t_list);
  ssh_time_measure_stop(ssh_timer);
  timer_value = (double)ssh_time_measure_get(ssh_timer,
                                             SSH_TIME_GRANULARITY_SECOND);
  if (verbose)
    printf("List reverse took %.2f ms (reverse is user implemented).\n", timer_value * 1000);

  /* mapcar test */
  ssh_time_measure_reset(ssh_timer);
  ssh_time_measure_start(ssh_timer);
  ssh_dllist_mapcar(t_list, remove_evens, NULL);
  ssh_time_measure_stop(ssh_timer);
  timer_value = (double)ssh_time_measure_get(ssh_timer,
                                             SSH_TIME_GRANULARITY_SECOND);
  if (verbose)
    printf("Remove evens with mapcar call, it took %.2f ms, elements left: %d\n",
           timer_value * 1000,
           ssh_dllist_length(t_list));
  if (ssh_dllist_length(t_list) != odds)
    ssh_fatal("t-dllist: invalid number of list elements after mapcar. Test failed.");

  if (verbose)
    printf("Freeing everything... ");
  ssh_time_measure_reset(ssh_timer);
  ssh_time_measure_start(ssh_timer);
  ssh_dllist_free(t_list);
  ssh_time_measure_stop(ssh_timer);
  timer_value = (double)ssh_time_measure_get(ssh_timer,
                                             SSH_TIME_GRANULARITY_SECOND);
  ssh_xfree(test_data);
  if (verbose)
    printf("OK, took %.2f ms (list had %d items).\n", timer_value * 1000, odds);

  return 0;
}
