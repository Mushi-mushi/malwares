/*

  sshcstack.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon May 26 13:34:57 1997 [mkojo]

  CStack & DStack routines. What is the difference? The CStack routines
  are allow destructors and thus are probably more difficult to use, DStack
  routines are very simple and perform just stacking and assume that data
  is freed somehow elsewhere.

  */

/*
 * $Id: sshcstack.h,v 1.1 1999/03/15 15:23:27 tri Exp $
 * $Log: sshcstack.h,v $
 * $EndLog$
 */

#ifndef CSTACK_H
#define CSTACK_H

/******* The CStack interface. *******/

typedef unsigned int SshCStackToken;

/* Our stack element looks like this, notice that you actually can
   add some additional fields using macros (or similar). */
typedef struct SshCStackRec
{
  SshCStackToken token;
  struct SshCStackRec *next;
  void (*destructor)(struct SshCStackRec *this);
} SshCStack;

/* Macro to ease our life :) If you don't like 'em don't use 'em. */

/* Macros to make the prefix for the structure. 'name' is some name you
   are willing to use. Use as follows:

   SSH_CSTACK_BEGIN( stack )
     char *hello_world;
   SSH_CSTACK_END( stack );

   */

#define SSH_CSTACK_BEGIN(name) \
typedef struct name##Rec  \
{                         \
  SshCStackToken token;   \
  SshCStack *next;        \
  void (*destructor)(SshCStack *this);

#define SSH_CSTACK_END(name) \
} name

/* Macros for generating the destructor code for prefixes. These are called
   having 'type' some selected type name, which you are willing to use.
   'name' some variable which you are willing to use. Then

   SSH_CSTACK_DESTRUCTOR_BEGIN( MyType, stack )
     free(stack->hello_world);
   SSH_CSTACK_DESTRUCTOR_END( MyType, stack )

   destroys your MyType structure.
   
   */

#define SSH_CSTACK_DESTRUCTOR_BEGIN(type, name) \
void ssh_cstack_##type##_destructor(SshCStack *name##_cstack) \
{                                   \
  type *name = (type *)name##_cstack;       \

#define SSH_CSTACK_DESTRUCTOR_END(type, name)       \
  ssh_xfree(name);                                          \
}

/* Macros for generating the constructor code for prefixes. Generates
   constructor with name e.g.

     MyType *ssh_cstack_MyType_constructor();

   use as

   SSH_CSTACK_CONSTRUCTOR_BEGIN( MyType, stack, context,
                                 MY_TYPE_DISTINCT_TOKEN )
     stack->hello_world = NULL;
   SSH_CSTACK_CONSTRUCTOR_END( MyType, stack )

   Note! if name differs in _BEGIN and _END then compiler will state
   an error.

   */

#define SSH_CSTACK_CONSTRUCTOR_BEGIN(type,stack_name,context_name,t) \
type *ssh_cstack_##type##_constructor(void *context_name) \
{                                      \
  type *stack_name = ssh_xmalloc(sizeof(*stack_name)); \
  stack_name->token = t;                                         

#define SSH_CSTACK_CONSTRUCTOR_END(type,name) \
  name->destructor = ssh_cstack_##type##_destructor; \
  return name;             \
}

/* Continuing the above example we can write with functions below:

   void my_example(char *str)
   {
     SshCStack *list = NULL;
     MyType *type = ssh_cstack_MyType_constructor(NULL),
            *temp;
     
     type->hello_world = malloc(strlen(str) + 1);
     if (type->hello_world == NULL)
       {
         ssh_cstack_MyType_destructor(type);
         exit(1);
       }

     strcpy(type->hello_world, str);
     
     ssh_cstack_push(&list, type);

     temp = ssh_cstack_pop(&list, MY_TYPE_DISTINCT_TOKEN);

     printf("%s\n", temp->hello_world);
     ssh_cstack_push(&list, temp);
     ssh_cstack_free(&list);
     if (list != NULL)
       exit(1);
   }


   called: my_example("Hello world!");

   output: Hello world!
   
 */


/* Push a element (this) into the stack pointed by (head). */
void ssh_cstack_push(SshCStack **head, void *this);

/* Pop element with (token) out of the stack. */
SshCStack *ssh_cstack_pop(SshCStack **head, SshCStackToken token);

/* Free the full stack. */
void *ssh_cstack_free(void *head);

/* Count number of elements of type token in the stack. */
unsigned int ssh_cstack_count(SshCStack **head, SshCStackToken token);

/******** DStack interface ********/

/* Following code implements a much more trivial stack system, which
   doesn't use destructors.

   This system is somewhat more useful if destructors are not needed,
   in fact, occasionally this is much better than the cstack routines.
   
   */

/* This is the only data structure needed and you don't need to do anything
   with its internals. */
typedef struct SshDStackRec
{
  struct SshDStackRec *next;
  void *data;
} SshDStack;

/* Following operations are defined: */

/* Pop an context out of the stack. Notice that the stack is given as a
   pointer to a pointer of the stack structure. That is the system will
   itself allocate new DStack entries and return you a new pointer. This
   allows one to start with a pointer set to NULL (allocated from
   the "real" stack).

   As is evident this system doesn't care what the data is that will be
   stored into the stack. 

   Function returns NULL if no more in stack.
   */
void *ssh_dstack_pop(SshDStack **stack);

/* Push a new context into the stack. Stack will grow as consequence. No
   limits are set so be careful. */
void ssh_dstack_push(SshDStack **stack, void *data);

/* One can get the first entry from the stack with this function. It returns
   NULL if stack is empty. */
void *ssh_dstack_current(SshDStack **stack);

/* Check whether the stack is empty or not. Returns FALSE if it is empty. */
Boolean ssh_dstack_exists(SshDStack **stack);

#endif /* CSTACK_H */
