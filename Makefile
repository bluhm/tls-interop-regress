PROG=		ssl_server
WARNINGS=	yes
LDADD=		-lssl -lcrypto
DPADD=		${LIBSSL} ${LIBCRYPTO}

.include <bsd.regress.mk>
