/*******************************************************************************
 *  The Elm Mail System  -  $Revision: 1.4 $   $State: Exp $
 *
 *                      Copyright (c) 1992 USENET Community Trust
 *******************************************************************************
 * Bug reports, patches, comments, suggestions should be sent to:
 *
 *      Syd Weinstein, Elm Coordinator
 *      elm@DSI.COM                     dsinc!elm
 *
 *******************************************************************************
 * $Log: putenv.c,v $
 * $EndLog$
 ******************************************************************************/

/*
 * This code was stolen from cnews.  Modified to make "newenv" static so
 * that realloc() can be used on subsequent calls to avoid memory leaks.
 *
 * We only need this if Configure said there isn't a putenv() in libc.
 */

#include "sshincludes.h"

/* peculiar return values */
#define WORKED 0
#define FAILED 1
#define YES 1
#define NO 0

int
putenv(var)                     /* put var in the environment */
char *var;
{
  register char **envp;
  register int oldenvcnt;
  extern char **environ;
  static char **newenv = NULL;
  
  /* count variables, look for var */
  for (envp = environ; *envp != 0; envp++) {
    register char *varp = var, *ep = *envp;
    register int namesame;
    
    namesame = NO;
    for (; *varp == *ep && *varp != '\0'; ++ep, ++varp)
      if (*varp == '=')
        namesame = YES;
    if (*varp == *ep && *ep == '\0')
      return WORKED;    /* old & new var's are the same */
    if (namesame) {
      *envp = var;      /* replace var with new value */
      return WORKED;
    }
  }
  oldenvcnt = envp - environ;
  
  /* allocate new environment with room for one more variable */
  if (newenv == NULL)
    newenv = (char **)ssh_xmalloc((unsigned)((oldenvcnt+1+1)*sizeof(*envp)));
  else
    newenv = (char **)ssh_xrealloc((char *)newenv, (unsigned)((oldenvcnt+1+1)*sizeof(*envp)));
  
  /* copy old environment pointers, add var, switch environments */
  memcpy((char *)newenv, (char *)environ, oldenvcnt*sizeof(*envp));
  newenv[oldenvcnt] = var;
  newenv[oldenvcnt+1] = NULL;
  environ = newenv;
  return WORKED;
}
