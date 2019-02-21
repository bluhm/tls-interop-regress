# $OpenBSD$

run-cipher-GOST2001-GOST89-GOST89-client-libressl-server-libressl:
	# cipher GOST2012256-GOST89-GOST89 is used in out file
	# TODO: figure out why it is not GOST2001
	@echo DISABLED

LIBRARIES =		libressl
.if exists(/usr/local/bin/eopenssl)
LIBRARIES +=		openssl
.endif
.if exists(/usr/local/bin/eopenssl11)
LIBRARIES +=		openssl11
.endif

CLEANFILES +=	*.tmp *.ciphers ciphers.mk

.for clib in ${LIBRARIES}
client-${clib}.ciphers:
	LD_LIBRARY_PATH=/usr/local/lib/e${clib} \
	    ../${clib}/client -L >$@.tmp
	sed -n 's/^cipher //p' <$@.tmp | sort -u >$@
	rm $@.tmp
.endfor
.for slib in ${LIBRARIES}
server-${slib}.ciphers: 127.0.0.1.crt dsa.crt ec.crt rsa.crt
	LD_LIBRARY_PATH=/usr/local/lib/e${slib} \
	    ../${slib}/server -L >$@.tmp
	sed -n 's/^cipher //p' <$@.tmp | sort -u >$@
	rm $@.tmp
.endfor

.for clib in ${LIBRARIES}
.for slib in ${LIBRARIES}
ciphers.mk: client-${clib}-server-${slib}.ciphers
client-${clib}-server-${slib}.ciphers: \
    client-${clib}.ciphers server-${slib}.ciphers
	sort client-${clib}.ciphers server-${slib}.ciphers >$@.tmp
	uniq -d <$@.tmp >$@
	rm $@.tmp
.endfor
.endfor

ciphers.mk:
	rm -f $@ $@.tmp
.for clib in ${LIBRARIES}
.for slib in ${LIBRARIES}
	echo 'CIPHERS_${clib}_${slib} =' >>$@.tmp \
	    `cat client-${clib}-server-${slib}.ciphers`
.endfor
.endfor
	mv $@.tmp $@

# what a dirty hack to convert generated lists into usable make variables
.if exists(ciphers.mk)
.include "ciphers.mk"
.else
regress: ciphers.mk
	${MAKE} -C ${.CURDIR} regress
.endif

.for clib in ${LIBRARIES}
.for slib in ${LIBRARIES}
.for cipher in ${CIPHERS_${clib}_${slib}}

.if "${cipher:M*-DSS-*}" != ""
TYPE_${cipher} =	dsa
.elif "${cipher:M*-ECDSA-*}" != ""
TYPE_${cipher} =	ec
.elif "${cipher:M*-GOST89-*}" != ""
TYPE_${cipher} =	gost
.elif "${cipher:M*-RSA-*}" != ""
TYPE_${cipher} =	rsa
.else
TYPE_${cipher} =	127.0.0.1
.endif

REGRESS_TARGETS +=	run-cipher-${cipher}-client-${clib}-server-${slib}
run-cipher-${cipher}-client-${clib}-server-${slib}: dh.param \
    127.0.0.1.crt ${TYPE_${cipher}}.crt ../${clib}/client ../${slib}/server
	@echo '\n======== $@ ========'
	LD_LIBRARY_PATH=/usr/local/lib/e${slib} \
	    ../${slib}/server >${@:S/^run/server/}.out \
	    -c ${TYPE_${cipher}}.crt -k ${TYPE_${cipher}}.key \
	    -l ${cipher} \
	    -p dh.param \
	    127.0.0.1 0
	LD_LIBRARY_PATH=/usr/local/lib/e${clib} \
	    ../${clib}/client >${@:S/^run/client/}.out \
	    -l ${cipher} \
	    `sed -n 's/listen sock: //p' ${@:S/^run/server/}.out`
	grep '^success$$' ${@:S/^run/server/}.out || \
	    { sleep 1; grep '^success$$' ${@:S/^run/server/}.out; }
	grep '^success$$' ${@:S/^run/client/}.out
	grep ' Cipher *: ${cipher}$$' ${@:S/^run/server/}.out
	grep ' Cipher *: ${cipher}$$' ${@:S/^run/client/}.out

.endfor
.endfor
.endfor

.include <bsd.regress.mk>
