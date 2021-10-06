# $FreeBSD$

PACKAGE=lib${LIB}
LIB=	vmmapi
SHLIB_MAJOR=	6
SRCS=	vmmapi.c vmmapi_freebsd.c
INCS=	vmmapi.h

LIBADD=	util

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${SRCTOP}/sys

CWARNFLAGS.vmmapi_freebsd.c+=-Wno-unused-parameter
CWARNFLAGS.vmmapi.c+=-Wno-unused-parameter

.include <bsd.lib.mk>
