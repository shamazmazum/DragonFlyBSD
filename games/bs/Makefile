# $FreeBSD: src/games/bs/Makefile,v 1.5.2.1 2001/04/25 09:28:49 ru Exp $

PROG=	bs
MAN=	bs.6
DPADD=	${LIBNCURSES}
LDADD=	-lprivate_ncurses
LDFLAGS+=	-rpath /lib/priv -L ${_SHLIBDIRPREFIX}/usr/lib/priv
HIDEGAME=hidegame

.include <bsd.prog.mk>
