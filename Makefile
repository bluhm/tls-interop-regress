PROG =		ssl_server
WARNINGS =	yes
LDADD =		-lssl -lcrypto
DPADD =		${LIBSSL} ${LIBCRYPTO}

run-regress-${PROG}: ${PROG} 127.0.0.1.crt

run-regress-${PROG}:
	./ssl_server | tee server.out
	nc -c -T noverify `sed -n 's/listen sock: //p'`

# create certificates for TLS

CLEANFILES +=	127.0.0.1.crt 127.0.0.1.key

127.0.0.1.crt:
	openssl req -batch -new -subj /L=OpenBSD/O=tls-regress/OU=ssl_server/CN=127.0.0.1/ -nodes -newkey rsa -keyout 127.0.0.1.key -x509 -out $@

.include <bsd.regress.mk>
