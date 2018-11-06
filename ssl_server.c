#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

void print_ciphers(STACK_OF(SSL_CIPHER) *);
void print_sockname(BIO *);

int
main(int argc, char *argv[])
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	unsigned long error;

	SSL_load_error_strings();

	method = TLS_server_method();
	if (method == NULL)
		err(1, "TLS_server_method");
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
		err(1, "SSL_CTX_new");
	ssl = SSL_new(ctx);
	if (ssl == NULL)
		err(1, "SSL_new");
	print_ciphers(SSL_CTX_get_ciphers(ctx));

	bio = BIO_new_accept("127.0.0.1:12345");
	if (bio == NULL)
		err(1, "BIO_new_accept");
	if (BIO_do_accept(bio) <= 0) {
		ERR_print_errors(bio);
		err(1, "BIO_do_accept setup");
	}
	print_sockname(bio);
	if (BIO_do_accept(bio) <= 0) {
		ERR_print_errors(bio);
		err(1, "BIO_do_accept wait");
	}

	SSL_set_bio(ssl, bio, bio);
	if (SSL_accept(ssl) <= 0) {
		error = ERR_get_error();
		fprintf(stderr, "%s\n", ERR_error_string(error, NULL));
		errx(1, "SSL_accept");
	}

	if (BIO_free(bio) <= 0) {
		ERR_print_errors(bio);
		err(1, "BIO_free");
	}
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}

void
print_ciphers(STACK_OF(SSL_CIPHER) *cstack)
{
	SSL_CIPHER *cipher;

	while ((cipher = sk_SSL_CIPHER_pop(cstack)) != NULL) {
		printf("%s\n", SSL_CIPHER_get_name(cipher));
	}
}

void
print_sockname(BIO *bio)
{
	struct sockaddr_storage lsock;
	socklen_t slen;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int fd;

	if (BIO_get_fd(bio, &fd) <= 0) {
		ERR_print_errors(bio);
		err(1, "BIO_get_fd");
	}
	slen = sizeof(lsock);
	if (getsockname(fd, (struct sockaddr *)&lsock, &slen) == -1)
		err(1, "getsockname");
	if (getnameinfo((struct sockaddr *)&lsock, lsock.ss_len, host,
	    sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV))
		errx(1, "getnameinfo");
	printf("listen sock: %s %s\n", host, port);
}
