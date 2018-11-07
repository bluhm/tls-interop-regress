# $OpenBSD: Makefile,v 1.1.1.1 2018/11/07 01:08:49 bluhm Exp $

.if ! exists(/usr/local/bin/eopenssl11)
regress:
	# install openssl11-1.1.1 from ports for interop tests
	@echo SKIPPED
.endif

PROGS =			client server
CPPFLAGS =		-I /usr/local/include/eopenssl11
LDFLAGS =		-L /usr/local/lib/eopenssl11
LDADD =			-lssl -lcrypto
DPADD =			/usr/local/lib/eopenssl11/libssl.a \
			/usr/local/lib/eopenssl11/libcrypto.a
LD_LIBRARY_PATH =	/usr/local/lib/eopenssl11

.for p in ${PROGS}
run-ldd-$p: ldd-$p.out
	@echo '\n======== $@ ========'
	# check that $p is linked with OpenSSL 1.1
	grep -q /usr/local/lib/eopenssl11/libcrypto.so ldd-$p.out
	grep -q /usr/local/lib/eopenssl11/libssl.so ldd-$p.out
	# check that $p is not linked with LibreSSL
	! grep -v libc.so ldd-$p.out | grep /usr/lib/
.endfor

.include <bsd.regress.mk>
