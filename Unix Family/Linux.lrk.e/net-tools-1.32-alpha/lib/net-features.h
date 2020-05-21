/*
 * lib/net-features.h	This file contains the definitions of all kernel
 *			dependend features.
 *
 * Version:	features.h 0.03 (1996-03-22)
 *
 * Author:	Bernd Eckenfels <net-tools@lina.inka.de>
 *		Copyright 1996 Bernd Eckenfels, Germany
 *
 * Modifications:
 *960201 {0.01}	Bernd Eckenfels:	creation
 *960202 {0.02}	Bernd Eckenfels:	HW and AF added
 *960322 {0.03}	Bernd Eckenfels:	moved into the NET-LIB
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 */

/* 
 *	This needs to be included AFTER the KErnel Header Files
 *	one of the FEATURE_ should be defined to get the Feature Variable
 *	definition included
 */
 
#ifndef _NET_FEATURES_H
#define _NET_FEATURES_H

/* detect the present features */

#ifdef IP_FW_F_MASQ /* ipfw */
#  define HAVE_FW_MASQUERADE 1
#endif

#ifdef IP_FW_F_APPEND /* ipfw */
#  define HAVE_FW_APPEND 1
#endif

#ifdef IP_FW_F_TCPACK /* ipfw */
#  define HAVE_FW_TCPACK 1
#endif

#ifdef OLD_SIOCSARP /* arp */
#  define HAVE_NEW_SIOCSARP 1
#endif

#if defined (SIOCADDRTOLD) || defined (RTF_IRTT) /* route */
#  define HAVE_NEW_ADDRT 1
#endif

#ifdef RTF_IRTT /* route */
#  define HAVE_RTF_IRTT 1
#endif

#ifdef RTF_REJECT /* route */
#  define HAVE_RTF_REJECT 1
#endif

#ifdef RTMSG_NEWROUTE /* netstat */
#  define HAVE_RT_NETLINK 1
#endif

/* compos the feature information string */

#if defined (FEATURE_IPFW) || defined (FEATURE_ARP) || defined (FEATURE_ROUTE) || defined (FEATURE_NETSTAT)
static char *Features=

/* ---------------------------------------------------- */
#ifdef FEATURE_IPFW

#  if HAVE_FW_MASQUERADE
	"+"
#  else 
	"-"
#  endif
	"FW_MASQUERADE "
	
#  if HAVE_FW_APPEND
	"+"
#  else
	"-"
#  endif
	"FW_APPEND "

#  if HAVE_FW_TCPACK
	"+"
#  else
	"-"
#  endif
	"FW_TCPACK "

#endif /* FEATURE_IPFW */
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
#ifdef FEATURE_ARP

#  if HAVE_NEW_SIOCSARP
	"+"
#  else 
	"-"
#  endif
	"NEW_SIOCSARP "
	
#endif /* FEATURE_ARP */
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
#ifdef FEATURE_ROUTE

#  if HAVE_NEW_ADDRT
	"+"
#  else
	"-"
#  endif
	"NEW_ADDRT "
	
#  if HAVE_RTF_IRTT
	"+"
#  else
	"-"
#  endif
	"RTF_IRTT "

#  if HAVE_RTF_REJECT
	"+"
#  else
	"-"
#  endif
	"RTF_REJECT "

#endif /* FEATURE_ROUTE */
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
#ifdef FEATURE_NETSTAT

#  if HAVE_NEW_ADDRT
	"+"
#  else
	"-"
#  endif
	"NEW_ADDRT "
	
#  if HAVE_RTF_IRTT
	"+"
#  else
	"-"
#  endif
	"RTF_IRTT "

#  if HAVE_RTF_REJECT
	"+"
#  else
	"-"
#  endif
	"RTF_REJECT "

#  if HAVE_RT_NETLINK
	"+"
#  else
	"-"
#  endif
	"RT_NETLINK "

#  if HAVE_FW_MASQUERADE
	"+"
#  else 
	"-"
#  endif
	"FW_MASQUERADE "

#endif /* FEATURE_NETSTAT */
/* ---------------------------------------------------- */


#if NLS
	"+NLS"
#else
	"-NLS"
#endif /* NLS */


"\nAF:"
#ifdef DFLT_AF
	"("DFLT_AF")"
#endif

#if HAVE_AFUNIX
	" +"
#else
	" -"
#endif
	"UNIX "
#if HAVE_AFINET
	"+"
#else
	"-"
#endif
	"INET "
#if HAVE_AFIPX
	"+"
#else
	"-"
#endif
	"IPX "
#if HAVE_AFAX25
	"+"
#else
	"-"
#endif
	"AX25 "
#if HAVE_AFNETROM 
	"+" 
#else
	"-"
#endif
	"NETROM "
#if HAVE_AFATALK
	"+"
#else
	"-"
#endif
	"ATALK "

"\nHW:"

#ifdef DFLT_HW
	"("DFLT_HW")"
#endif

#if HAVE_HWETHER
	" +"
#else
	" -"
#endif
	"ETHER "
#if HAVE_HWARC
	"+"
#else
	"-"
#endif
	"ARC "
#if HAVE_HWSLIP
	"+"
#else
	"-"
#endif
	"SLIP "
#if HAVE_HWPPP
	"+"
#else
	"-"
#endif
	"PPP "
#if HAVE_HWTUNNEL
	"+"
#else
	"-"
#endif
	"TUNNEL "
#if HAVE_HWTR
	"+"
#else
	"-"
#endif
	"TR "
#if HAVE_HWAX25
	"+"
#else
	"-"
#endif
	"AX25 "
	
#if HAVE_HWNETROM
	"+"
#else
	"-"
#endif
	"NETROM "

#if HAVE_HWFR
	"+"
#else
	"-"
#endif
	"FR ";


#endif /* FEATURE_* */

#endif /* _NET_FEATURES_H */
/* End of features.h */
