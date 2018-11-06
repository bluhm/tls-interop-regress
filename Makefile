PROG =		ssl_server
WARNINGS =	yes
LDADD =		-lssl -lcrypto
DPADD =		${LIBSSL} ${LIBCRYPTO}

run-regress-${PROG}: ${PROG} 127.0.0.1.crt

run-regress-${PROG}:
	./ssl_server >server.out
	echo "hello" | nc -c -T noverify\
	    `sed -n 's/listen sock: //p' server.out`\
	    >client.out
	# check that the server child run successfully to the end
	grep -q '^success$$' server.out
	# server must have read client hello
	grep -q '^<<< hello$$' server.out
	# client must have read server greeting
	grep -q '^greeting$$' client.out

# create certificates for TLS

CLEANFILES +=	127.0.0.1.crt 127.0.0.1.key

127.0.0.1.crt:
	openssl req -batch -new -subj /L=OpenBSD/O=tls-regress/OU=ssl_server/CN=127.0.0.1/ -nodes -newkey rsa -keyout 127.0.0.1.key -x509 -out $@

.include <bsd.regress.mk>
