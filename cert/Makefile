# $OpenBSD$

.if ! exists(/usr/local/bin/eopenssl) || ! exists(/usr/local/bin/eopenssl11)
regress:
	# install openssl-1.0.2p and openssl-1.1.1 from ports
	@echo SKIPPED
.endif

CLEANFILES +=	client.out server.out

.for clib in libressl openssl openssl11
.for slib in  libressl openssl openssl11
.for cca in noca ca fakeca
.for sca in noca ca fakeca
.for ccert in nocert cert
.for scert in nocert cert
.for cv in noverify verify
.for sv in noverify verify

REGRESS_TARGET +=	\
run-client-${clib}-${cca}-${ccert}-${cv}-server-${slib}-${sca}-${scert}-${sv}
run-client-${clib}-${cca}-${ccert}-${cv}-server-${slib}-${sca}-${scert}-${sv}:\
    ca.crt fake-ca.crt client.crt server.crt \
    ../${clib}/client ../${slib}/server
	@echo '\n======== $@ ========'
	LD_LIBRARY_PATH=/usr/local/lib/e${slib} ../${slib}/server >server.out \
	    ${sca:S/^noca//:S/^fakeca/-C fake-ca.crt/:S/^ca/-C ca.crt/} \
	    ${scert:S/^nocert//:S/^cert/-c server.crt -k server.key/} \
	    ${sv:S/^noverify//:S/^verify/-v/} \
	    127.0.0.1 0
	LD_LIBRARY_PATH=/usr/local/lib/e${clib} ../${clib}/client >client.out \
	    ${cca:S/^noca//:S/^fakeca/-C fake-ca.crt/:S/^ca/-C ca.crt/} \
	    ${ccert:S/^nocert//:S/^cert/-c server.crt -k server.key/} \
	    ${cv:S/^noverify//:S/^verify/-v/} \
	    `sed -n 's/listen sock: //p' server.out`
	grep -q '^success$$' server.out
	grep -q '^success$$' client.out

.endfor
.endfor
.endfor
.endfor
.endfor
.endfor
.endfor
.endfor

.include <bsd.regress.mk>
