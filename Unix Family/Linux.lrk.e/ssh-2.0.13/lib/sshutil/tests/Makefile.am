## Process this file with automake to produce Makefile.in

#
# lib/sshutil/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

TESTS = t-buffer t-crc32 t-replace t-snprintf t-malloc t-encode \
	t-timemeasure t-dllist \
	t-stream t-socks t-streampair t-localstream t-mapping t-udp \
	t-asn1 t-base64 t-sshutf8 t-psystem t-filexfer t-url \
	t-inet_ntoa t-dsprintf t-time

# t-parser t-uf

EXTRA_PROGRAMS = t-buffer t-crc32 t-encode \
	t-timemeasure t-dllist \
	t-stream t-replace \
	t-snprintf t-malloc t-socks t-streampair t-localstream \
	t-mapping t-udp \
	t-asn1 t-base64 t-sshutf8 t-psystem t-filexfer t-url t-serial \
	t-sshlist t-inet_ntoa t-debug t-dns t-dsprintf t-time

LDADD = ../libsshutil.a ../../sshmath/libsshmath.a
INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/..  \
	-I$(top_builddir) -I$(top_srcdir) 	\
	-I../../sshmath -I$(srcdir)/../../sshmath -I../../sshscard \
	-I../../sshcrypt -I../../trq

t_buffer_SOURCES = t-buffer.c
t_buffer_DEPENDENCIES = $(LDADD)
t_crc32_SOURCES = t-crc32.c
t_crc32_DEPENDENCIES = $(LDADD)
t_dns_SOURCES = t-dns.c
t_dns_DEPENDENCIES = $(LDADD)
t_encode_SOURCES = t-encode.c
t_encode_DEPENDENCIES = $(LDADD)
t_timemeasure_SOURCES = t-timemeasure.c
t_timemeasure_DEPENDENCIES = $(LDADD)
t_dllist_SOURCES = t-dllist.c
t_dllist_DEPENDENCIES = $(LDADD)
t_stream_SOURCES = t-stream.c
t_stream_DEPENDENCIES = $(LDADD)
t_streampair_SOURCES = t-streampair.c
t_streampair_DEPENDENCIES = $(LDADD)
t_localstream_SOURCES = t-localstream.c
t_localstream_DEPENDENCIES = $(LDADD)
t_replace_SOURCES = t-replace.c
t_replace_DEPENDENCIES = $(LDADD)
t_snprintf_SOURCES = t-snprintf.c
t_snprintf_DEPENDENCIES = $(LDADD)
t_malloc_SOURCES = t-malloc.c
t_malloc_DEPENDENCIES = $(LDADD)
t_socks_SOURCES = t-socks.c
t_socks_DEPENDENCIES = $(LDADD)
t_mapping_SOURCES = t-mapping.c
t_mapping_DEPENDENCIES = $(LDADD)
t_udp_SOURCES = t-udp.c
t_udp_DEPENDENCIES = $(LDADD)
t_asn1_SOURCES = t-asn1.c
t_asn1_DEPENDENCIES = $(LDADD)
t_psystem_SOURCES = t-psystem.c
t_psystem_DEPENDENCIES = $(LDADD)
t_base64_SOURCES = t-base64.c
t_base64_DEPENDENCIES = $(LDADD)
t_sshutf8_SOURCES = t-sshutf8.c
t_sshutf8_DEPENDENCIES = $(LDADD)
t_filexfer_SOURCES = t-filexfer.c
t_filexfer_DEPENDENCIES = $(LDADD)
t_url_SOURCES = t-url.c
t_url_DEPENDENCIES = $(LDADD)
t_serial_SOURCES = t-serial.c
t_serial_DEPENDENCIES = $(LDADD)
t_sshlist_SOURCES = t-sshlist.c
t_sshlist_DEPENDENCIES = $(LDADD)
t_inet_ntoa_SOURCES = t-inet_ntoa.c
t_inet_ntoa_DEPENDENCIES = $(LDADD)
t_debug_SOURCES = t-debug.c
t_debug_DEPENDENCIES = $(LDADD)
t_dsprintf_SOURCES = t-dsprintf.c
t_dsprintf_DEPENDENCIES = $(LDADD)
