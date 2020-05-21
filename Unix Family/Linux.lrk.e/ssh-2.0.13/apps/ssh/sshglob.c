
#include "sshincludes.h"
#include "sshglob.h"

#define SSH_DEBUG_MODULE "SshGlob"
/*                                                               shade{0.9}
 * This function checks for wildcards (currently only '*') in a
 * string. Parameter str must be a valid null-terminated string. If
 * wildcards are found, returns TRUE. Otherwise, returns
 * FALSE. Wildcards (and every other character too) can be escaped
 * with a backslash ('\'). Doesn't modify the original string.
 *                                                               shade{1.0}
 */
Boolean scp_check_wildcards(char *str)
{
  int len = 0, i = 0;
  Boolean wildcards_present = FALSE;
  
  SSH_PRECOND(str);
  len = strlen(str);
  
  for (i = 0; i < len; i++)
    {
      /* If a character is escaped, jump over it. */
      if (str[i] == '\\')
        {
          if (str[i + 1] != '\0')
            {        
              i++;
            }
          else
            {
              break;
            }
        }
      else if (strchr(SSH_WILDCARDS, str[i]))
        {
          wildcards_present = TRUE;
        }    
    }
  
  return wildcards_present;
}

