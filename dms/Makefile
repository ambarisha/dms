# $FreeBSD$
.include <bsd.own.mk>

SRCS=		utils.c list.c dms.c worker.c
PROG=		dms
CSTD?=		c99
.if ${MK_OPENSSL} != "no"
DPADD=		${LIBFETCH} ${LIBSSL} ${LIBCRYPTO}
LDADD=		-lfetch -lssl -lcrypto
.else
DPADD=		${LIBFETCH}
LDADD=		-lfetch
.endif

.include <bsd.prog.mk>
