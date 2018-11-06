# $OpenBSD$

.PATH:			${.CURDIR}/..

LDADD =			-lssl -lcrypto
DPADD ?=		${LIBSSL} ${LIBCRYPTO}
WARNINGS =		yes
REGRESS_TARGETS	=

# check that program is linked with correct libraries

.for p in ${PROGS}
CLEANFILES +=		ldd-$p.out
REGRESS_TARGETS +=	run-ldd-$p
ldd-$p.out: $p
	LD_LIBRARY_PATH=${LD_LIBRARY_PATH} ldd $p >$@
.endfor

# run test server and connect with netcat client

CLEANFILES +=		server.out client.out
REGRESS_TARGETS +=	run-server
run-server: server 127.0.0.1.crt
	@echo '\n======== $@ ========'
	LD_LIBRARY_PATH=${LD_LIBRARY_PATH} ./server >server.out
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

CLEANFILES +=		127.0.0.1.crt 127.0.0.1.key

127.0.0.1.crt:
	openssl req -batch -new -subj /L=OpenBSD/O=tls-regress/OU=server/CN=127.0.0.1/ -nodes -newkey rsa -keyout 127.0.0.1.key -x509 -out $@
