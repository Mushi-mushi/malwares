/* util.h
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_UTIL_H
#define G10_UTIL_H

#include "types.h"
#include "errors.h"
#include "types.h"
#include "mpi.h"


typedef struct {
     int  *argc;	    /* pointer to argc (value subject to change) */
     char ***argv;	    /* pointer to argv (value subject to change) */
     unsigned flags;	    /* Global flags (DO NOT CHANGE) */
     int err;		    /* print error about last option */
			    /* 1 = warning, 2 = abort */
     int r_opt; 	    /* return option */
     int r_type;	    /* type of return value (0 = no argument found)*/
     union {
	 int   ret_int;
	 long  ret_long;
	 ulong ret_ulong;
	 char *ret_str;
     } r;		    /* Return values */
     struct {
	 int idx;
	 int inarg;
	 int stopped;
	 const char *last;
	 void *aliases;
	 const void *cur_alias;
     } internal;	    /* DO NOT CHANGE */
} ARGPARSE_ARGS;

typedef struct {
    int 	short_opt;
    const char *long_opt;
    unsigned flags;
    const char *description; /* optional option description */
} ARGPARSE_OPTS;

/*-- logger.c --*/
void log_set_logfile( const char *name, int fd );
FILE *log_stream(void);
void log_set_name( const char *name );
const char *log_get_name(void);
void log_set_pid( int pid );
int  log_get_errorcount( int clear );
void log_inc_errorcount(void);

void rsa_log_fatal( const char *fmt, ... );
void rsa_log( const char *fmt, ... );
#define BUG() {}

#define log_hexdump rsa_log
#define log_bug     rsa_log
#define log_bug0    rsa_log_fatal
#define log_fatal   rsa_log_fatal
#define log_error   rsa_log_fatal
#define log_info    rsa_log
#define log_debug   rsa_log
#define log_fatal_f g10_log_fatal_f
#define log_error_f g10_log_error_f
#define log_info_f  g10_log_info_f
#define log_debug_f g10_log_debug_f


/*-- errors.c --*/
const char * g10_errstr( int no );

/*-- argparse.c --*/
int arg_parse( ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts);
int optfile_parse( FILE *fp, const char *filename, unsigned *lineno,
		   ARGPARSE_ARGS *arg, ARGPARSE_OPTS *opts);
void usage( int level );
const char *default_strusage( int level );


/*-- (main program) --*/
const char *strusage( int level );


/*-- dotlock.c --*/
struct dotlock_handle;
typedef struct dotlock_handle *DOTLOCK;

void disable_dotlock(void);
DOTLOCK create_dotlock( const char *file_to_lock );
int make_dotlock( DOTLOCK h, long timeout );
int release_dotlock( DOTLOCK h );


/*-- fileutil.c --*/
char * make_basename(const char *filepath);
char * make_dirname(const char *filepath);
char *make_filename( const char *first_part, ... );
int compare_filenames( const char *a, const char *b );
const char *print_fname_stdin( const char *s );
const char *print_fname_stdout( const char *s );


/*-- miscutil.c --*/
u32 make_timestamp(void);
u32 scan_isodatestr( const char *string );
u32 add_days_to_timestamp( u32 stamp, u16 days );
const char *strtimevalue( u32 stamp );
const char *strtimestamp( u32 stamp ); /* GMT */
const char *asctimestamp( u32 stamp ); /* localized */
void print_string( FILE *fp, const byte *p, size_t n, int delim );
void  print_utf8_string( FILE *fp, const byte *p, size_t n );
char *make_printable_string( const byte *p, size_t n, int delim );
int answer_is_yes( const char *s );
int answer_is_yes_no_quit( const char *s );

/*-- strgutil.c --*/
void free_strlist( STRLIST sl );
#define FREE_STRLIST(a) do { free_strlist((a)); (a) = NULL ; } while(0)
STRLIST add_to_strlist( STRLIST *list, const char *string );
STRLIST add_to_strlist2( STRLIST *list, const char *string, int is_utf8 );
STRLIST append_to_strlist( STRLIST *list, const char *string );
STRLIST append_to_strlist2( STRLIST *list, const char *string, int is_utf8 );
STRLIST strlist_prev( STRLIST head, STRLIST node );
STRLIST strlist_last( STRLIST node );
const char *memistr( const char *buf, size_t buflen, const char *sub );
char *mem2str( char *, const void *, size_t);
char *trim_spaces( char *string );
unsigned trim_trailing_chars( byte *line, unsigned len, const char *trimchars);
unsigned trim_trailing_ws( byte *line, unsigned len );
int string_count_chr( const char *string, int c );
int set_native_charset( const char *newset );
const char* get_native_charset(void);
char *native_to_utf8( const char *string );
char *utf8_to_native( const char *string, size_t length );
int  check_utf8_string( const char *string );

#ifndef HAVE_MEMICMP
int memicmp( const char *a, const char *b, size_t n );
#endif
#ifndef HAVE_STPCPY
char *stpcpy(char *a,const char *b);
#endif
#ifndef HAVE_STRLWR
char *strlwr(char *a);
#endif
#ifndef HAVE_STRCASECMP
int strcasecmp( const char *, const char *b);
#endif
#ifndef HAVE_STRTOUL
  #define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
  #define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
  #define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif

/*-- w32reg.c --*/
#ifdef __MINGW32__
char *read_w32_registry_string( const char *root,
				const char *dir, const char *name );
#endif

/**** other missing stuff ****/
#ifndef HAVE_ATEXIT  /* For SunOS */
  #define atexit(a)    (on_exit((a),0))
#endif

#ifndef HAVE_RAISE
  #define raise(a) kill(getpid(), (a))
#endif

/******** some macros ************/
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

#endif /*G10_UTIL_H*/
