/*
 * pathnames	This file contains the definitions of the path names used
 *		by the NET base distribution.  Do not change the values!
 *
 * Version:	@(#)pathnames.h	1.30	09/06/93
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 */

/* Pathnames of base-level NET programs. */
#define _PATH_BIN_NETSTAT	"/bin/netstat"
#define _PATH_BIN_HOSTNAME	"/bin/hostname"
#define _PATH_BIN_DOMAINNAME	"/bin/domainname"
#define _PATH_BIN_IFSETUP	"/sbin/ifsetup"
#define _PATH_BIN_IFCONFIG	"/sbin/ifconfig"
#define _PATH_BIN_ROUTE		"/sbin/route"
#define _PATH_BIN_ARP		"/sbin/arp"

/* Pathnames of the PROCfs files used by NET. */
#if 1
# define _PATH_PROCNET_TCP	"/proc/net/tcp"
# define _PATH_PROCNET_UDP	"/proc/net/udp"
# define _PATH_PROCNET_RAW	"/proc/net/raw"
# define _PATH_PROCNET_UNIX	"/proc/net/unix"
# define _PATH_PROCNET_ROUTE	"/proc/net/route"
# define _PATH_PROCNET_ARP	"/proc/net/arp"
#else
# define _PATH_PROCNET_TCP	"/dev/net/tcp"
# define _PATH_PROCNET_UDP	"/dev/net/udp"
# define _PATH_PROCNET_RAW	"/dev/net/raw"
# define _PATH_PROCNET_UNIX	"/proc/net/unix"
# define _PATH_PROCNET_ROUTE	"/proc/net/route"
# define _PATH_PROCNET_ARP	"/proc/net/arp"
#endif

/* Pathnames of the various device files used by NET. */
#define _PATH_DEV_ARP		"/dev/net/arp"
#define _PATH_DEV_SOCKET	"/dev/net/socket"

/* Pathnames of some customizable files. */
#define _PATH_ETC_DIPHOSTS	"/etc/diphosts"
#define _PATH_DIP_PID		"/etc/dip.pid"

#define _PATH_LOCKD		"/var/spool/uucp"	/* lock files	*/

#define _UID_UUCP		"uucp"			/* owns locks	*/

/* End of pathnames.h */
