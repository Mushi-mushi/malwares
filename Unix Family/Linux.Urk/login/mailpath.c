#include "sys_defs.h"

#include <stdio.h>
#include <sys/param.h>
#include <string.h>

char   *realpath();

#define	_PATH_MAILDIR	"/var/spool/mail"

 /* Macros to hide the differences between SunOS 4.x and SunOS 5.x. */

#ifdef USE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#define _PATH_MTAB		"/etc/mnttab"
#define SETMNTENT(file,mode)	fopen(file,mode)
#define GETMNTENT(fp,mp)	(getmntent(fp, mp) == 0)
#define ENDMNTENT(fp)		fclose(fp)
#define SPECIAL(mp)		(mp)->mnt_special
#define MOUNTPOINT(mp)		(mp)->mnt_mountp
#else
#include <mntent.h>
#define _PATH_MTAB		"/etc/mtab"
#define SETMNTENT(file,mode)	setmntent(file,mode)
#define GETMNTENT(fp,mp)	((mp = getmntent(fp)) != 0)
#define ENDMNTENT(fp)		endmntent(fp)
#define SPECIAL(mp)		(mp)->mnt_fsname
#define MOUNTPOINT(mp)		(mp)->mnt_dir
#endif

/* mailpath - map homedir to mailbox path */

char   *mail_path(home, user)
char   *home;
char   *user;
{
    static char mailpath[BUFSIZ];
    char    home_info[BUFSIZ];
    char    real_home[MAXPATHLEN];
    FILE   *fp;
    int     longest_match = 0;
    int     len_mountp;
    char   *cp;
#ifdef SYSV4
    struct mnttab mnt;
#define mp (&mnt)
#else
    struct mntent *mp;
#endif

    /*
     * Try to deduce mailpath from home directory mount information. Use
     * /var/spool/mail/user when the mount is local, otherwise insert the
     * unqualified name of the home directory file server before the
     * username.
     */

    if (realpath(home, real_home) && (fp = SETMNTENT(_PATH_MTAB, "r")) != 0) {
	while (GETMNTENT(fp, mp)) {
	    len_mountp = strlen(MOUNTPOINT(mp));
	    if (len_mountp > longest_match && real_home[len_mountp] == '/'
		&& strncmp(real_home, MOUNTPOINT(mp), len_mountp) == 0) {
		longest_match = len_mountp;
		strcpy(home_info, SPECIAL(mp));
	    }
	}
	ENDMNTENT(fp);
    }

    /*
     * If the home directory comes from a remote host the filesystem name is
     * of the form host:/some/path. Truncate the host to unqualified form.
     */

    if (longest_match > 0 && (cp = strchr(home_info, ':')) != 0) {
	*cp = 0;
	if ((cp = strchr(home_info, '.')) != 0)
	    *cp = 0;
	sprintf(mailpath, "%s/%s/%s", _PATH_MAILDIR, home_info, user);
    } else {
	sprintf(mailpath, "%s/%s", _PATH_MAILDIR, user);
    }
    return (mailpath);
}

#ifdef STANDALONE

#include <pwd.h>

main()
{
    struct passwd *pwd;

    if ((pwd = getpwuid(getuid())) == 0) {
	fprintf(stderr, "Who are you?\n");
	exit(1);
    }
    printf("%s\n", mail_path(pwd->pw_dir, pwd->pw_name));
}

#endif
