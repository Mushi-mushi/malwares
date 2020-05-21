/*
 * $Id: zbin2oct.c, just a bin=>octal convertor
 */

#include <stdio.h>
#include <stdlib.h>

#define	WRAP	17

int	main()
{
	int	c;
	int	pos = 0;
	printf("\"");
	while ((c = getchar()) != EOF) {
		printf("\\%03o", c);
		pos++;
		if (pos == WRAP) {
			printf("\\\n");
			pos = 0;
		}
	}
	putchar('\"');
	if (pos) {
		putchar('\n');
	}
	return 0;
}
