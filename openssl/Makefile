# $OpenBSD$

.if ! exists(/usr/local/bin/eopenssl)
regress:
	# install openssl-1.0.2p from ports for interop tests
	@echo SKIPPED
.endif

PROG =			server
CPPFLAGS =		-I /usr/local/include/eopenssl
LDFLAGS =		-L /usr/local/lib/eopenssl
LDADD =			-lssl -lcrypto
DPADD =			/usr/local/lib/eopenssl/libssl.a \
			/usr/local/lib/eopenssl/libcrypto.a
LD_LIBRARY_PATH =	/usr/local/lib/eopenssl

run-ldd-${PROG}: ldd-${PROG}.out
	# check that ${PROG} is linked with OpenSSL
	grep -q /usr/local/lib/eopenssl/libcrypto.so ldd-${PROG}.out
	grep -q /usr/local/lib/eopenssl/libssl.so ldd-${PROG}.out
	# check that ${PROG} is not linked with LibreSSL 
	! grep -v libc.so ldd-${PROG}.out | grep /usr/lib/

.include <bsd.regress.mk>
