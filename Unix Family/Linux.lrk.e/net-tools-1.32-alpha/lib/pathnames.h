/*
 * lib/pathnames.h	This file contains the definitions of the path 
 *			names used by the NET-LIB. Do not change the values!
 *
 * NET-LIB	
 *
 * Version:	lib/pathnames.h 1.36 (1996-04-13)
 *
 * Maintainer:	Bernd 'eckes' Eckenfels, <net-tools@lina.inka.de>
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *
 * Modification:
 *960125 {1.31}	Bernd Eckenfels: 	Major cleanup, junk removed.
 *960131 {1.32}	Bernd Eckenfels:	/proc/net/ip_*
 *960204 {1.33} Bernd Eckenfels:	/dev/net/route
 *960215 {1.34} Bernd Eckenfels:	/proc/net/ax25_route,nr_*
 *960322 {1.35} Bernd Eckenfels:	moved to the lib directory
 *960413 {1.36} Bernd Eckenfels:	/proc/net/rt_cache
 *
 */

/* Pathnames of the PROCfs files used by NET. */

# define _PATH_PROCNET_TCP		"/proc/net/tcp"
# define _PATH_PROCNET_UDP		"/proc/net/udp"
# define _PATH_PROCNET_RAW		"/proc/net/raw"
# define _PATH_PROCNET_UNIX		"/proc/net/unix"
# define _PATH_PROCNET_ROUTE		"/proc/net/route"
# define _PATH_PROCNET_RTCACHE		"/proc/net/rt_cache"
# define _PATH_PROCNET_AX25_ROUTE	"/proc/net/ax25_route"
# define _PATH_PROCNET_NR		"/proc/net/nr"
# define _PATH_PROCNET_NR_NEIGH		"/proc/net/nr_neigh"
# define _PATH_PROCNET_NR_NODES		"/proc/net/nr_nodes"
# define _PATH_PROCNET_ARP		"/proc/net/arp"
# define _PATH_PROCNET_AX25		"/proc/net/ax25"
# define _PATH_PROCNET_IPX		"/proc/net/ipx"
# define _PATH_PROCNET_IPX_ROUTE	"/proc/net/ipx_route"
# define _PATH_PROCNET_ATALK		"/proc/net/appletalk"
# define _PATH_PROCNET_IP_BLK		"/proc/net/ip_block"
# define _PATH_PROCNET_IP_FWD		"/proc/net/ip_forward"
# define _PATH_PROCNET_IP_ACC		"/proc/net/ip_acct"
# define _PATH_PROCNET_IP_MASQ		"/proc/net/ip_masquerade"


/* Pathnames for the Netlink Devices */

# define _PATH_DEV_ROUTE	"/dev/route"



/* End of pathnames.h */
