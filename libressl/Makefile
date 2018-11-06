# $OpenBSD$

PROG =			ssl_server
CPPFLAGS =
LDFLAGS =
LDADD =			-lssl -lcrypto
DPADD =			${LIBSSL} ${LIBCRYPTO}
LD_LIBRARY_PATH =

run-ldd-${PROG}: ldd-${PROG}.out
	# check that ${PROG} is linked with LibreSSL
	grep -q /usr/lib/libcrypto.so ldd-${PROG}.out
	grep -q /usr/lib/libssl.so ldd-${PROG}.out
	# check that ${PROG} is not linked with OpenSSL
	! grep /usr/local/lib/ ldd-${PROG}.out

.include <bsd.regress.mk>
