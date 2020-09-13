# $OpenBSD$

# Connect a client to a server.  Both can be current libressl, or
# openssl 1.0.2, or openssl 1.1.  Pin client or server to a fixed
# TLS version number.  Check that client and server have used
# correct version by grepping in their session print out.

LIBRARIES =		libressl
.if exists(/usr/local/bin/eopenssl)
LIBRARIES +=		openssl
.endif
.if exists(/usr/local/bin/eopenssl11)
LIBRARIES +=		openssl11
.endif

VERSIONS =	any TLS1 TLS1_1 TLS1_2 TLS1_3

.for cver in ${VERSIONS}
.for sver in ${VERSIONS}

.if "${cver}" == any || "${sver}" == any || "${cver}" == "${sver}"
FAIL_${cver}_${sver} =
.else
FAIL_${cver}_${sver} = !
.endif

.for clib in ${LIBRARIES}
.for slib in ${LIBRARIES}

.if ("${clib}" != openssl && "${slib}" != openssl) || \
    ("${cver}" != TLS1_3 && "${sver}" != TLS1_3)

REGRESS_TARGETS +=	run-version-${cver}-${sver}-${clib}-${slib}

run-version-${cver}-${sver}-${clib}-${slib} \
client-version-${cver}-${sver}-${clib}-${slib}.out \
server-version-${cver}-${sver}-${clib}-${slib}.out: \
    127.0.0.1.crt ../${clib}/client ../${slib}/server
	@echo '\n======== $@ ========'
	LD_LIBRARY_PATH=/usr/local/lib/e${slib} \
	    ../${slib}/server >${@:S/^run/server/}.out \
	    -c 127.0.0.1.crt -k 127.0.0.1.key \
	    ${sver:Nany:S/^/-V /} \
	    127.0.0.1 0
	${FAIL_${cver}_${sver}} \
	LD_LIBRARY_PATH=/usr/local/lib/e${clib} \
	    ../${clib}/client >${@:S/^run/client/}.out \
	    ${cver:Nany:S/^/-V /} \
	    `sed -n 's/listen sock: //p' ${@:S/^run/server/}.out`
.if empty(${FAIL_${cver}_${sver}})
	grep -q '^success$$' ${@:S/^run/server/}.out || \
	    { sleep 1; grep -q '^success$$' ${@:S/^run/server/}.out; }
	grep -q '^success$$' ${@:S/^run/client/}.out
.else
	echo XXX
.endif

#REGRESS_TARGETS +=	check-version-${cver}-${sver}-${clib}-${slib}

check-version-${cver}-${sver}-${clib}-${slib}: \
    client-version-${cver}-${sver}-${clib}-${slib}.out \
    server-version-${cver}-${sver}-${clib}-${slib}.out
	@echo '\n======== $@ ========'
	@grep ' Protocol *: ' ${@:S/^check/client/}.out
	@grep ' Protocol *: ' ${@:S/^check/server/}.out
	grep -q ' Protocol *: ${cver:C/S/Sv/:C/_/./}$$' ${@:S/^check/client/}.out
	grep -q ' Protocol *: ${sver:C/S/Sv/:C/_/./}$$' ${@:S/^check/server/}.out

.endif

.endfor
.endfor
.endfor
.endfor

.include <bsd.regress.mk>
