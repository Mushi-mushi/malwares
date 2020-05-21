#include <sys/types.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define	FBTAB		"/etc/fbtab"
#define LOGINDEVPERM	"/etc/logindevperm"
#define	WSPACE		" \t\n"

/* login_fbtab - apply protections specified in /etc/fbtab or logindevperm */

login_fbtab(tty, uid, gid)
char   *tty;
int     uid;
int     gid;
{
    FILE   *fp;
    char    buf[BUFSIZ];
    char   *devname;
    char   *cp;
    int     prot;
    char *table;

    if ((fp = fopen(table = FBTAB, "r")) == 0
    && (fp = fopen(table = LOGINDEVPERM, "r")) == 0)
	return;

    while (fgets(buf, sizeof(buf), fp)) {
	if (cp = strchr(buf, '#'))
	    *cp = 0;				/* strip comment */
	if ((cp = devname = strtok(buf, WSPACE)) == 0)
	    continue;				/* empty or comment */
	if (strncmp(devname, "/dev/", 5) != 0
	       || (cp = strtok((char *) 0, WSPACE)) == 0
	       || *cp != '0'
	       || sscanf(cp, "%o", &prot) == 0
	       || prot == 0
	       || (prot & 0777) != prot
	       || (cp = strtok((char *) 0, WSPACE)) == 0) {
	    syslog(LOG_ERR, "%s: bad entry: %s", table, cp ? cp : "(null)");
	    continue;
	}
	if (strcmp(devname + 5, tty) == 0) {
	    for (cp = strtok(cp, ":"); cp; cp = strtok((char *) 0, ":")) {
		login_protect(table, cp, prot, uid, gid);
	    }
	}
    }
    fclose(fp);
}

/* login_protect - protect one device entry */

login_protect(table, path, mask, uid, gid)
char *table;
char *path;
int mask;
int uid;
int gid;
{
    char    buf[BUFSIZ];
    int     pathlen = strlen(path);
    struct dirent *ent;
    DIR    *dir;

    if (strcmp("/*", path + pathlen - 2) != 0) {
	if (chmod(path, mask) && errno != ENOENT)
	    syslog(LOG_ERR, "%s: chmod(%s): %m", table, path);
	if (chown(path, uid, gid) && errno != ENOENT)
	    syslog(LOG_ERR, "%s: chown(%s): %m", table, path);
    } else {
	strcpy(buf, path);
	buf[pathlen - 1] = 0;
	if ((dir = opendir(buf)) == 0) {
	    syslog(LOG_ERR, "%s: opendir(%s): %m", table, path);
	} else {
	    while ((ent = readdir(dir)) != 0) {
		if (strcmp(ent->d_name, ".") != 0
		    && strcmp(ent->d_name, "..") != 0) {
		    strcpy(buf + pathlen - 1, ent->d_name);
		    login_protect(table, buf, mask, uid, gid);
		}
	    }
	    closedir(dir);
	}
    }
}
