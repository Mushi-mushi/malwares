/* acconfig.h
   This file is in the public domain.

   Descriptive text for the C preprocessor macros that
   the distributed Autoconf macros can define.
   No software package will use all of them; autoheader copies the ones
   your configure.in uses into your configuration header file templates.

   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  Although this order
   can split up related entries, it makes it easier to check whether
   a given entry is in the file.

   Leave the following blank line there!!  Autoheader needs it.  */


/* Define if you have the Andrew File System.  */
#undef AFS

/* Define to `unsigned long' if <sys/types.h> doesn't define.  */
#undef ino_t

/* Define if there is a member named d_ino in the struct describing
   directory headers.  */
#undef D_INO_IN_DIRENT


/* Define one of the following to indicate how a program can
   get a list of mounted filesystems.  */

/* Define if there is no specific function for reading the list of
   mounted filesystems.  fread will be used to read /etc/mnttab.  [SVR2]  */
#undef MOUNTED_FREAD

/* Define if (like SVR2) there is no specific function for reading the
   list of mounted filesystems, and your system has these header files:
   <sys/fstyp.h> and <sys/statfs.h>.  [SVR3]  */
#undef MOUNTED_FREAD_FSTYP

/* Define if there is a function named getfsstat for reading the list
   of mounted filesystems.  [DEC Alpha running OSF/1]  */
#undef MOUNTED_GETFSSTAT

/* Define if there is a function named getmnt for reading the list of
   mounted filesystems.  [Ultrix]  */
#undef MOUNTED_GETMNT

/* Define if there is a function named getmntent for reading the list
   of mounted filesystems, and that function takes a single argument.
   [4.3BSD, SunOS, HP-UX, Dynix, Irix]  */
#undef MOUNTED_GETMNTENT1

/* Define if there is a function named getmntent for reading the list of
   mounted filesystems, and that function takes two arguments.  [SVR4]  */
#undef MOUNTED_GETMNTENT2

/* Define if there is a function named getmntinfo for reading the list
   of mounted filesystems.  [4.4BSD]  */
#undef MOUNTED_GETMNTINFO

/* Define if there is a function named mntctl that can be used to read
   the list of mounted filesystems, and there is a system header file
   that declares `struct vmount.'  [AIX]  */
#undef MOUNTED_VMOUNT




/* Define one of the following to indicate how a program can obtain
   filesystems usage information.  */

/*  Define if  statfs takes 3 args.  [DEC Alpha running OSF/1]  */
#undef STAT_STATFS3_OSF1

/* Define if there is no specific function for reading filesystems usage
   information and you have the <sys/filsys.h> header file.  [SVR2]  */
#undef STAT_READ_FILSYS

/* Define if statfs takes 2 args and struct statfs has a field named f_bsize.
   [4.3BSD, SunOS 4, HP-UX, AIX PS/2]  */
#undef STAT_STATFS2_BSIZE

/* Define if statfs takes 2 args and struct statfs has a field named f_fsize.
   [4.4BSD, NetBSD]  */
#undef STAT_STATFS2_FSIZE

/* Define if statfs takes 2 args and the second argument has
   type struct fs_data.  [Ultrix]  */
#undef STAT_STATFS2_FS_DATA

/* Define if statfs takes 4 args.  [SVR3, Dynix, Irix, Dolphin]  */
#undef STAT_STATFS4

/* Define if there is a function named statvfs.  [SVR4]  */
#undef STAT_STATVFS


/* Leave that blank line there!!  Autoheader needs it.
   If you're adding to this file, keep in mind:
   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  */
