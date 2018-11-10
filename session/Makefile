# $OpenBSD$

CLEANFILES +=		*.out

.for clib in libressl openssl openssl11
.for slib in libressl openssl openssl11

REGRESS_TARGETS +=	run-client-${clib}-reuse-server-${slib}-reuse

run-client-${clib}-reuse-server-${slib}-reuse: 127.0.0.1.crt
	@echo '\n======== $@ ========'
	LD_LIBRARY_PATH=/usr/local/lib/e${slib} \
	    ../${slib}/server -s >server-${clib}-reuse.out \
	    127.0.0.1 0
	LD_LIBRARY_PATH=/usr/local/lib/e${clib} \
	    ../${clib}/client -s >client-${clib}-reuse.out \
	    `sed -n 's/listen sock: //p' server-${slib}-reuse.out`
	grep '^success$$' server-${slib}-reuse.out
	grep '^success$$' client-${clib}-reuse.out

.endfor
.endfor

.include <bsd.regress.mk>
