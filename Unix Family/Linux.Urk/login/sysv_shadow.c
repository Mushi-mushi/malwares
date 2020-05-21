#include <pwd.h>
#include <shadow.h>

/* sysv_expire - check account and password expiration times */

sysv_expire(spwd)
struct spwd *spwd;
{
    long    today;
    char    buf[BUFSIZ];

    tzset();
    today = DAY_NOW;

    if (spwd->sp_expire > 0) {
	if (today > spwd->sp_expire) {
	    printf("Your account has expired.\n");
	    sleepexit(1);
	} else if (spwd->sp_expire - today < 14) {
	    printf("Your account will expire in %d days.\n",
		   spwd->sp_expire - today);
	    return (0);
	}
    }
    if (spwd->sp_max > 0) {
	if (today > (spwd->sp_lstchg + spwd->sp_max)) {
	    printf("Your password has expired. Choose a new one.\n");
	    return (1);
	} else if (spwd->sp_warn > 0
	    && (today > (spwd->sp_lstchg + spwd->sp_max - spwd->sp_warn))) {
	    printf("Your password will expire in %d days.\n",
		   spwd->sp_lstchg + spwd->sp_max - today);
	    return (0);
	}
    }
    return (0);
}
