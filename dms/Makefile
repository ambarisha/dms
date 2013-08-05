# $FreeBSD$
.include <bsd.own.mk>

SRCS=		mirror.c utils.c dms.c worker.c
PROG=		dms
CSTD?=		c99
.if ${MK_OPENSSL} != "no"
DPADD=		${LIBFETCH} ${LIBSSL} ${LIBCRYPTO}
LDADD=		-lfetch -lssl -lcrypto -lpthread
.else
DPADD=		${LIBFETCH}
LDADD=		-lfetch
.endif
CFLAGS+=	-g

.include <bsd.prog.mk>
