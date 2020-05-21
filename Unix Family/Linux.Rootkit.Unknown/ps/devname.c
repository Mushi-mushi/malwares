/*
 * devname.c
 *
 * modified by Michael K. Johnson, johnsonm@sunsite.unc.edu for YAPPS
 * 
 * I am changing this significantly to provide a more reasonable
 * output.  Two characters are not enough to easily grok all possible
 * tty's.
 * 
 * $Log: devname.c,v $
 * Revision 1.8  1994/07/27  06:35:20  cb
 * decided that snap.c was the place to do the minor device no
 * conversion after all.  At least for now.  re-writing the
 * tty_to_dev() routine is what made me think that it was just much easier
 * to use only the minor number while doing ps stuff.
 *
 * Revision 1.7  1994/07/27  05:38:34  cb
 * added a macro TTY_FULL_DEVNO to correct for the presence of the major bits
 * for the only current tty major device.  Later this may need to be generalized.
 * If a kernel past 1.1.?? (not sure which patch level) is used then defining
 * this macro should be uncommented out of the Makefile.
 *
 * Revision 1.6  1994/01/01  12:43:47  johnsonm
 * Fixed dev3().
 *
 * Revision 1.5  1993/12/31  20:22:13  johnsonm
 * Removed devline perversion from my wrong-ended attempts to fix w.
 *
 */

#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <string.h>
#include <stdio.h>

static char rcsid[]="$Id: devname.c,v 1.8 1994/07/27 06:35:20 cb Exp $";

/*
 * ttynames:
 *    console: con              console
 *       vc00: v01 v02...       virtual consoles
 *      tty00: s00 s01...       serial lines
 *      ttyp0: p00 p01...       pty's
 */

static char *ttgrp = "    StuvPQRWpqrs";
static char *ttsub = "0123456789abcdef";

void dev_to_tty(char *tty, int dev)
{
  if (dev == -1)
    strcpy(tty," ? ");
  else if (dev == 0)
    strcpy(tty,"con");
  else if (dev < 64) {
    sprintf(tty, "v%02d", dev);
  } else {
    if (dev < 128) {
      sprintf(tty, "s%02d", (dev - 64));
    } else {
      tty[0] = 'p';
      tty[1] = ttgrp[(dev >> 4) & 017];
      tty[2] = ttsub[dev & 017];
    }
  }
  tty[3] = 0;
}

int tty_to_dev(char *tty)
{
    char *p, *q;
    int i;

    if (tty == (char*)0) {
        fprintf(stderr, "devname.c: tty_to_dev() called with null argument\n");
        exit(1);
    }
    if (*tty == '\0') {		/* empty string: controlling tty */
	struct stat buf;
	if (fstat(0, &buf) != -1)
	    return(buf.st_rdev & 0xff);
	else
	    return -1;
    }
    if (tty[0] == 'v') {
        sscanf(&tty[1], "%d", &i);
	return(i);
    }
    if (tty[0] == 's') {
        sscanf(&tty[1], "%d", &i);
	return(i+64);
    }
    if (tty[0] == 'p') {
        p = strchr(ttgrp, tty[1]);
	q = strchr(ttsub, tty[2]);
	return(((p - ttgrp) << 4) | (q - ttsub));
    }
    if ((strcmp(tty, "con") == 0) || (strcmp(tty, "co") == 0))
	return(0);
    /* The rest are for compatibility with old releases */
    if (tty[1] == '\0' && *tty >= '0' && *tty <= '9')
	return(*tty - '0');
    if ((p = strchr(ttgrp, *tty)) != NULL &&
	(q = strchr(ttsub, tty[1])) != NULL)
	return(((p - ttgrp) << 4) | (q - ttsub));
    else
	return -1;
}

char *dev3(char *ttyname)
{
    static char ftname[256]; /* holds filename, then ttyname */
    struct stat sb;

    strcpy(ftname, "/dev/");
    strcat(ftname, ttyname);
    stat(ftname, &sb);
    if (S_ISCHR(sb.st_mode))
    {
        dev_to_tty(ftname, MINOR(sb.st_rdev));
    }
    else
    {
        strcpy(ftname, " ? ");
    }
    return(ftname);
}
