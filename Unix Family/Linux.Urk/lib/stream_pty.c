#include <sys/types.h>
#include <sys/stream.h>
#include <errno.h>
#include <stropts.h>
#include <syslog.h>
#include <termio.h>
#include <termios.h>
#include "tiocpkt.h"

/* pty_pkt_read - convert SYSV pty packets to BSD pty packets */

int     pty_pkt_read(fd, buf, len)
int     fd;
char   *buf;
int     len;
{
    struct strbuf ctl;
    struct strbuf data;
    char    cbuf[100];
    char    dbuf[100];
    int     flags;
    int     ret;
    struct iocblk iocblk;
    struct termio termio;
    struct termios termios;
    static int old_flow = -1;
    int     new_flow;

    /*
     * Convert SYSV pckt-style messages (M_XXX) to BSD pty-style packets
     * (TIOCPKT_XXX). References: SunOS 5.1 Streams Programmer's Guide,
     * chapter 12; the 386BSD0.1 pty(4) manual page. The types of output we
     * produce: TIOCPKT_DATA, TIOCPKT_START, TIOCPKT_STOP, TIOCKPT_FLUSHREAD,
     * TIOCPKT_FLUSHWRITE, TIOCPKT_DOSTOP, TIOCPKT_NOSTOP.
     * 
     * Rather than imposing alignment constraints on the input buffer, we make
     * copies of ioctl control structures. The loss of performance should be
     * negligible. Most of the time we will be dealing with non-control
     * messages anyway.
     * 
     * Requests for one-byte reads (i.e. for non-data messages) are assumed to
     * be requests for priority messages. This is the best we can do, given
     * the semantical differences between select() and poll(). There really
     * is no way to read non-data messages only.
     * 
     * If no output is produced, set errno to EAGAIN and try again later.
     */

    if (len == 1) {
	flags = RS_HIPRI;
	data.maxlen = sizeof(dbuf);
	data.buf = dbuf;
    } else {
	flags = 0;
	data.maxlen = len - 1;
	data.buf = buf + 1;
    }
    ctl.maxlen = sizeof(cbuf);
    ctl.buf = cbuf;

    if (ret = getmsg(fd, &ctl, &data, &flags) < 0)
	return (ret);
    switch (ctl.len) {
    default:
	syslog(LOG_ERR, "bad pckt control message length %d", ctl.len);
	break;
    case -1:					/* more data */
    case 0:
	buf[0] = TIOCPKT_DATA;
	return (data.len + 1);
    case 1:
	switch (ctl.buf[0] & 0377) {
	case M_DATA:				/* regular data message */
	    buf[0] = TIOCPKT_DATA;
	    return (data.len > 0 ? data.len + 1 : 0);
	case M_FLUSH:				/* flush (some) queues */
	    switch (data.buf[0] & FLUSHRW) {
	    case FLUSHW:			/* output only */
		buf[0] = TIOCPKT_FLUSHWRITE;
		return (1);
	    case FLUSHR:			/* input only */
		buf[0] = TIOCPKT_FLUSHREAD;
		return (1);
	    case FLUSHRW:			/* output and input */
		buf[0] = TIOCPKT_FLUSHWRITE | TIOCPKT_FLUSHREAD;
		return (1);
	    default:				/* ?!none?! */
		break;
	    }
	    break;
	case M_STOP:				/* suspend output */
	    buf[0] = TIOCPKT_STOP;
	    return (1);
	case M_START:				/* resume output */
	    buf[0] = TIOCPKT_START;
	    return (1);
#ifdef M_STOPI
	case M_STOPI:				/* suspend input */
	case M_STARTI:				/* resume input */
	    /* no equivalent yet */
	    break;
#endif
	case M_IOCTL:				/* check flow control status */
	    memcpy(&iocblk, data.buf, sizeof(iocblk));
	    switch (iocblk.ioc_cmd) {
#ifdef TCSETS
	    case TCSETS:
	    case TCSETSW:
	    case TCSETSF:
		memcpy(&termios, data.buf + sizeof(iocblk), sizeof(termios));
		new_flow = (termios.c_cc[VSTOP] == 21
			    && termios.c_cc[VSTART] == 23
			    && (termios.c_iflag & IXON));
		if (old_flow != new_flow) {
		    old_flow = new_flow;
		    buf[0] = (new_flow ? TIOCPKT_DOSTOP : TIOCPKT_NOSTOP);
		    return (1);
		}
		break;
#endif
	    case TCSETA:
	    case TCSETAW:
	    case TCSETAF:
		memcpy(&termio, data.buf + sizeof(iocblk), sizeof(termio));
		new_flow = (termio.c_cc[VSTOP] == 21
			    && termio.c_cc[VSTART] == 23
			    && (termio.c_iflag & IXON));
		if (old_flow != new_flow) {
		    old_flow = new_flow;
		    buf[0] = (new_flow ? TIOCPKT_DOSTOP : TIOCPKT_NOSTOP);
		    return (1);
		}
		break;
	    default:
		break;
	    }
	}
	break;
    }
    /* No output produced - try again later. */

    errno = EAGAIN;
    return (-1);
}
