/*	$OpenBSD$	*/
/*
 * Copyright (c) 2019-2020 Alexander Bluhm <bluhm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <unistd.h>

#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>

#include <iostream>
#include <string>
using namespace std;

class Callbacks : public Botan::TLS::Callbacks {
public:
	Callbacks(int socket) :
		m_socket(socket)
	{}
	void print_sockname()
	{
		struct sockaddr_storage ss;
		char host[NI_MAXHOST], port[NI_MAXSERV];
		socklen_t slen;

		slen = sizeof(ss);
		if (getsockname(m_socket, (struct sockaddr *)&ss, &slen) == -1)
			err(1, "getsockname");
		if (getnameinfo((struct sockaddr *)&ss, ss.ss_len, host,
		    sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV))
			errx(1, "getnameinfo");
		cout << "sock: " << host << " " << port << endl << flush;

	}
	void print_peername()
	{
		struct sockaddr_storage ss;
		char host[NI_MAXHOST], port[NI_MAXSERV];
		socklen_t slen;

		slen = sizeof(ss);
		if (getpeername(m_socket, (struct sockaddr *)&ss, &slen) == -1)
			err(1, "getpeername");
		if (getnameinfo((struct sockaddr *)&ss, ss.ss_len, host,
		    sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV))
			errx(1, "getnameinfo");
		cout <<"peer: " <<host <<" " <<port <<endl <<flush;

	}
	void tls_emit_data(const uint8_t data[], size_t size) override
	{
		size_t off = 0, len = size;

		while (len > 0) {
			ssize_t n;

			n = send(m_socket, data + off, len, 0);
			if (n < 0)
				err(1, "send");
			off += n;
			len -= n;
		}
	}
	void tls_record_received(uint64_t seq_no, const uint8_t data[],
	    size_t size) override
	{
		cout <<">>> " <<string((const char *)data, size) <<flush;
	}
	void tls_alert(Botan::TLS::Alert alert) override
	{
		errx(1, "alert: %s", alert.type_string().c_str());
	}
	bool tls_session_established(const Botan::TLS::Session& session)
	    override
	{

		cout <<"established" <<endl;
		// the session with the tls server was established
		// return false to prevent the session from being cached, true to
		// cache the session in the configured session manager
		return false;
	}

protected:
	int m_socket = -1;
};

class Credentials : public Botan::Credentials_Manager {
public:
	std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
	    const std::string  &type, const std::string  &context)
	    override
	{
		std::vector<Botan::Certificate_Store*> cs { &m_ca };
		return cs;
	}

	void add_certificate_file(const std::string &file) {
		Botan::X509_Certificate cert(file);
		m_ca.add_certificate(cert);
	}
private:
	Botan::Certificate_Store_In_Memory m_ca;
};

void __dead
usage(void)
{
	fprintf(stderr, "usage: client [-C CA] host port\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	struct addrinfo hints, *res;
	int ch, s, error;
	char buf[256];
	char *cafile = NULL;
	char *host, *port;

	while ((ch = getopt(argc, argv, "C:")) != -1) {
		switch (ch) {
		case 'C':
			cafile = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 2) {
		host = argv[0];
		port = argv[1];
	} else {
		usage();
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	if (res == NULL)
		errx(1, "getaddrinfo empty");
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s == -1)
		err(1, "socket");
	if (connect(s, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "connect");
	freeaddrinfo(res);

	Callbacks callbacks(s);
	Botan::AutoSeeded_RNG rng;
	Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
	Credentials creds;
	if (cafile != NULL)
		creds.add_certificate_file(cafile);
	Botan::TLS::Strict_Policy policy;

	callbacks.print_sockname();
	callbacks.print_peername();
	Botan::TLS::Client client(callbacks, session_mgr, creds, policy, rng);

	while (!client.is_closed()) {
		ssize_t n;

		n = recv(s, buf, sizeof(buf), 0);
		if (n < 0)
			err(1, "recv");
		if (n == 0)
			errx(1, "eof");
		n = client.received_data((uint8_t *)&buf, n);
		if (n == 0)
			break;
	}
	string str("Hello\n");
	cout <<">>> " <<str <<flush;
	client.send(str);

	return 0;
}
