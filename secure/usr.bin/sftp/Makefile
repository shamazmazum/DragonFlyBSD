# $FreeBSD: src/secure/usr.bin/sftp/Makefile,v 1.1.2.3 2002/07/03 22:20:30 des Exp $

PROG=	sftp
SRCS=	progressmeter.c sftp.c sftp-client.c sftp-common.c sftp-glob.c roaming_dummy.c
WARNS?=	0

# Portability layer
SRCS+=	fmt_scaled.c

DPADD+=	${LIBEDIT} ${LIBTERMCAP}
LDADD+=	-lprivate_edit -lprivate_termcap
LDFLAGS+=	-rpath /lib/priv -L ${_SHLIBDIRPREFIX}/usr/lib/priv

.include "../../Makefile.ssh.common"
.include <bsd.prog.mk>
