AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I.
AM_CFLAGS = -Wall
nc_SOURCES = netcat.c getopt.c getopt1.c
noinst_HEADERS = getopt.h
nc_LDADD = @LIBOBJS@
bin_PROGRAMS = nc
dist_man1_MANS = nc.1
dist_noinst_HEADERS = poll_.h
info_TEXINFOS = netcat.texi
EXTRA_DIST = README-alpha \
	data/Makefile data/README data/data.c data/dns-any.d \
	data/nfs-0.d data/pm.d data/pmap-dump.d data/pmap-mnt.d \
	data/rip.d data/rservice.c data/showmount.d data/xor.c \
	scripts/README scripts/alta scripts/bsh scripts/dist.sh \
	scripts/irc scripts/iscan scripts/ncp scripts/probe \
	scripts/web scripts/webproxy scripts/webrelay scripts/websearch

DISTCLEANFILES = poll.h
