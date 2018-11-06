#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

void print_ciphers(STACK_OF(SSL_CIPHER) *);
void print_sockname(BIO *);
void err_ssl(int, const char *, ...);

int
main(int argc, char *argv[])
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	SSL_SESSION *session;
	int error;

	SSL_library_init();
	SSL_load_error_strings();

	/* setup method and context */
	method = TLS_server_method();
	if (method == NULL)
		err_ssl(1, "TLS_server_method");
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
		err_ssl(1, "SSL_CTX_new");

	/* load server certificate */
	if (SSL_CTX_use_certificate_file(ctx, "127.0.0.1.crt",
	    SSL_FILETYPE_PEM) <= 0)
		err_ssl(1, "SSL_CTX_use_certificate_file");
	if (SSL_CTX_use_PrivateKey_file(ctx, "127.0.0.1.key",
	    SSL_FILETYPE_PEM) <= 0)
		err_ssl(1, "SSL_CTX_use_PrivateKey_file");
	if (SSL_CTX_check_private_key(ctx) <= 0)
		err_ssl(1, "SSL_CTX_check_private_key");

	print_ciphers(SSL_CTX_get_ciphers(ctx));

	/* setup ssl and bio for socket operations */
	ssl = SSL_new(ctx);
	if (ssl == NULL)
		err_ssl(1, "SSL_new");
	bio = BIO_new_accept("127.0.0.1:12345");
	if (bio == NULL)
		err_ssl(1, "BIO_new_accept");
	SSL_set_bio(ssl, bio, bio);

	/* bind, listen, accept */
	if (BIO_do_accept(bio) <= 0)
		err_ssl(1, "BIO_do_accept setup");
	print_sockname(bio);
	if (BIO_do_accept(bio) <= 0)
		err_ssl(1, "BIO_do_accept wait");

	/* do ssl server handshake */
	if ((error = SSL_accept(ssl)) <= 0)
		err_ssl(1, "SSL_accept %d", error);

	/* print session statistics */
	session = SSL_get_session(ssl);
	if (session == NULL)
		err_ssl(1, "SSL_get_session");
	if (SSL_SESSION_print_fp(stdout, session) <= 0)
		err_ssl(1, "SSL_SESSION_print_fp");

	/* shutdown connection */
	if ((error = SSL_shutdown(ssl)) < 0)
		err_ssl(1, "SSL_shutdown unidirectional %d", error);
	if ((error = SSL_shutdown(ssl)) <= 0)
		err_ssl(1, "SSL_shutdown bidirectional %d", error);

	/* cleanup and free resources */
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

void
print_ciphers(STACK_OF(SSL_CIPHER) *cstack)
{
	SSL_CIPHER *cipher;
	int i;

	for (i = 0; (cipher = sk_SSL_CIPHER_value(cstack, i)) != NULL; i++)
		printf("cipher %s\n", SSL_CIPHER_get_name(cipher));
}

void
print_sockname(BIO *bio)
{
	struct sockaddr_storage lsock;
	socklen_t slen;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int fd;

	if (BIO_get_fd(bio, &fd) <= 0)
		err_ssl(1, "BIO_get_fd");
	slen = sizeof(lsock);
	if (getsockname(fd, (struct sockaddr *)&lsock, &slen) == -1)
		err(1, "getsockname");
	if (getnameinfo((struct sockaddr *)&lsock, lsock.ss_len, host,
	    sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV))
		errx(1, "getnameinfo");
	printf("listen sock: %s %s\n", host, port);
}

void
err_ssl(int eval, const char *fmt, ...)
{
	va_list ap;

	ERR_print_errors_fp(stderr);
	va_start(ap, fmt);
	verrx(eval, fmt, ap);
	va_end(ap);
}
