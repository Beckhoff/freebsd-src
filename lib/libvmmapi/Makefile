# $FreeBSD$

PACKAGE=lib${LIB}
LIB=	vmmapi
SRCS=	vmmapi.c vmmapi_freebsd.c
INCS=	vmmapi.h

WARNS?=	2

LIBADD=	util

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${SRCTOP}/sys

.include <bsd.lib.mk>
