# $FreeBSD: src/lib/libpthread/Makefile,v 1.53 2004/10/24 15:32:32 ru Exp $
# $DragonFly: src/lib/libthread_xu/Makefile,v 1.7 2008/10/28 17:23:46 swildner Exp $

LIB=thread_xu
SHLIB_MAJOR= 2
CFLAGS+=-DPTHREAD_KERNEL -D_THREAD_SAFE
CFLAGS+=-I${.CURDIR}/../libc/include -I${.CURDIR}/thread \
	-I${.CURDIR}/../../include
CFLAGS+=-I${.CURDIR}/arch/${MACHINE_ARCH}/include
CFLAGS+=-I${.CURDIR}/../libthread_db

# CFLAGS+=-DSYSTEM_SCOPE_ONLY

# XXX this breaks threaded applications
#LDFLAGS=-Wl,-version-script=${.CURDIR}/pthread.map

# enable extra internal consistancy checks
CFLAGS+=-D_PTHREADS_INVARIANTS

# This library cannot be reloaded, so prevent its unload
LDFLAGS+=-Wl,-znodelete

PRECIOUSLIB=	yes

LIBDIR=	/usr/lib/thread
NOPROFILE=	yes

WARNS?=	5

.include "${.CURDIR}/arch/${MACHINE_ARCH}/Makefile.inc"
.include "${.CURDIR}/thread/Makefile.inc"

.include <bsd.lib.mk>
