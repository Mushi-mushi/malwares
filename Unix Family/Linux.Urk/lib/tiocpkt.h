/* Definitions for OOB message data */

#define	TIOCPKT_DATA		0x00	/* data packet */
#define	TIOCPKT_FLUSHREAD	0x01	/* flush data not yet written */
#define	TIOCPKT_FLUSHWRITE	0x02	/* flush data read from */
#define	TIOCPKT_STOP		0x04	/* stop output */
#define	TIOCPKT_START		0x08	/* start output */
#define	TIOCPKT_NOSTOP		0x10	/* no more ^S, ^Q */
#define	TIOCPKT_DOSTOP		0x20	/* now do ^S, ^Q */
#define	TIOCPKT_IOCTL		0x40	/* "ioctl" packet */
