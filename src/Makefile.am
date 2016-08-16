#
# $Id$
#

noinst_LIBRARIES = libgateway.a

bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
wifidog_LDADD = libgateway.a $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = main.c \
		iwlib.c \
		iwevent.c \
		gateway.c \
		ssl.c

libgateway_a_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw_iptables.c \
	firewall.c \
	centralserver.c \
	http.c \
	auth.c \
	client_list.c \
	util.c \
	wdctl_thread.c \
	ping_thread.c \
	safe.c \
	httpd_thread.c \
	simple_http.c \
	pstring.c \
	wd_util.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw_iptables.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h \
	client_list.h \
	util.h \
	wdctl_thread.h \
	wdctl.h \
	ping_thread.h \
	safe.h \
	httpd_thread.h \
	simple_http.h \
	pstring.h \
	wd_util.h \
	iwlib.h \
	wireless_event_thread.h \
	br_event.h \
	ssl.h \
 	cp_main.h \
 	cp_debug.h
	

wdctl_LDADD = libgateway.a

wdctl_SOURCES = wdctl.c
