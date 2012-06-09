# Copyright (C) 2006, 2009 Free Software Foundation, Inc.
# This Makefile.am is free software; the Free Software Foundation
# gives unlimited permission to copy, distribute and modify it.

lib_LTLIBRARIES = libmew.la
libmew_la_SOURCES = config.c connector.c curl.c connector_webdav.c connector_ftp.c crypto.c ipc.c metadata.c
libmew_la_LDFLAGS = -version-info 1:1:0
AM_CFLAGS = $(LIBDEPS_CFLAGS)
libmew_la_LIBADD = $(LIBDEPS_LIBS)
