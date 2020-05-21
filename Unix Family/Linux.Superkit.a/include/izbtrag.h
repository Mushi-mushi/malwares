#define UTMP            "/var/run/utmp"
#define WTMP            "/var/log/wtmp"
#define LASTLOG         "/var/log/lastlog"
#define MESSAGES        "/var/log/messages"
#define SECURE          "/var/log/secure"
#define XFERLOG         "/var/log/xferlog"
#define MAILLOG         "/var/log/maillog"
#define WARN            "/var/log/warn"
#define MAIL            "/var/log/mail"
#define HTTPDA          "/var/log/httpd/access_log"
#define HTTPDE          "/var/log/httpd/error_log"
#define MAXBUFF         8*1024

#define ERR(a) {\
fprintf(stderr,"%s: ",pg);\
perror(a);\
exit(1);\
}

#define BASENAME(a) {\
if((pg=(char *)strrchr(a,'/'))) {\
pg++;\
}\
else {\
pg=a;\
}\
}

#define USAGE(a) {\
fprintf(stderr,"Usage: %s %s\n",pg,a);\
exit(1);\
}

char *pg;

#define RK_PROG	pg
