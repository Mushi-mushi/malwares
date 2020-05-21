/*

  cstack.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon May 26 13:33:44 1997 [mkojo]

  CStack & DStack routines, which denotes that these are mainly used in
  crypto library... :) Of course they can be used elsewhere also. If
  someone can figure out better names I'd be glad to know.

  Moved to sshutil where they make better sense.
  
  */

/*
 * $Id: sshcstack.c,v 1.1 1999/03/15 15:23:26 tri Exp $
 * $Log: sshcstack.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcstack.h"

void ssh_cstack_push(SshCStack **head, void *this)
{
  SshCStack *stack = this;
  stack->next = *head;
  *head = stack;
}

unsigned int ssh_cstack_count(SshCStack **head, SshCStackToken token)
{
  SshCStack *temp;
  unsigned int count;
  for (temp = *head, count = 0; temp; temp = temp->next)
    if (temp->token == token)
      count++;
  return count;
}

SshCStack *ssh_cstack_pop(SshCStack **head, SshCStackToken token)
{
  SshCStack *temp, *prev;

  temp = *head;
  prev = NULL;
  while (temp)
    {
      /* Compare */
      if (temp->token == token)
        {
          /* Remove from list (our stack). */
          if (prev)
            prev->next = temp->next;
          else
            *head = temp->next;
          temp->next = NULL;
          break;
        }
      prev = temp;
      temp = temp->next;
    }

  /* Return either NULL or valid stack entry. */
  return temp;
}

/* Implemented with pop and push, which is nice :) */
SshCStack *ssh_cstack_find(SshCStack **head, SshCStackToken token)
{
  SshCStack *temp;

  temp = ssh_cstack_pop(head, token);
  if (temp)
    {
      ssh_cstack_push(head, temp);
      temp = *head;
    }
  return temp;
}

/* Free any stack element or stack itself! */
void *ssh_cstack_free(void *head)
{
  SshCStack *temp, *temp2;

  temp = head;
  while (temp)
    {
      temp2 = temp->next;
      /* Free. */
      (*temp->destructor)(temp);
      temp = temp2;
    }

  /* Tell upper-layer that all were freed successfully. */
  return NULL;
}

/* This is the implementation for the simpler stack system. Useful
   also occasionally. */
   
void *ssh_dstack_pop(SshDStack **stack)
{
  void *data;
  SshDStack *next;

  if (stack == NULL)
    return NULL;
  
  if (*stack != NULL)
    {
      data = (*stack)->data;
      next = (*stack)->next;
      ssh_xfree(*stack);
      *stack = next;
      return data;
    }
  return NULL;
}

void ssh_dstack_push(SshDStack **stack, void *data)
{
  SshDStack *node;
  if (stack == NULL)
    return;
  
  node = ssh_xmalloc(sizeof(*node));
  node->data = data;
  node->next = *stack;
  *stack = node;
}

void *ssh_dstack_current(SshDStack **stack)
{
  if (stack == NULL)
    return NULL;
  
  if (*stack)
    return (*stack)->data;
  return NULL;
}

Boolean ssh_dstack_exists(SshDStack **stack)
{
  if (stack == NULL)
    return FALSE;
  if (*stack == NULL)
    return FALSE;
  return TRUE;
}

/* cstack.c */
