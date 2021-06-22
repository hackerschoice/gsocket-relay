#include "common.h"

struct _gopt gopt;
struct _g_debug_ctx g_dbg_ctx;

int
main()
{

BIO *sbio, *bbio, *acpt, *out;
 int len;
 char tmpbuf[1024];
 SSL_CTX *ctx;
 SSL *ssl;

 /* XXX Seed the PRNG if needed. */

 ctx = SSL_CTX_new(TLS_server_method());
 if (!SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM)
         || !SSL_CTX_use_PrivateKey_file(ctx, "server.pem", SSL_FILETYPE_PEM)
         || !SSL_CTX_check_private_key(ctx)) {
     fprintf(stderr, "Error setting up SSL_CTX\n");
     ERR_print_errors_fp(stderr);
     exit(1);
 }

 /* XXX Other things like set verify locations, EDH temp callbacks. */

 /* New SSL BIO setup as server */
 sbio = BIO_new_ssl(ctx, 0);
 BIO_get_ssl(sbio, &ssl);
 if (ssl == NULL) {
     fprintf(stderr, "Can't locate SSL pointer\n");
     ERR_print_errors_fp(stderr);
     exit(1);
 }

 SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 bbio = BIO_new(BIO_f_buffer());
 sbio = BIO_push(bbio, sbio);
 acpt = BIO_new_accept("4433");

 /*
  * By doing this when a new connection is established
  * we automatically have sbio inserted into it. The
  * BIO chain is now 'swallowed' by the accept BIO and
  * will be freed when the accept BIO is freed.
  */
 BIO_set_accept_bios(acpt, sbio);
 out = BIO_new_fp(stdout, BIO_NOCLOSE);

 /* Setup accept BIO */
 if (BIO_do_accept(acpt) <= 0) {
     fprintf(stderr, "Error setting up accept BIO\n");
     ERR_print_errors_fp(stderr);
     exit(1);
 }

 if (BIO_do_accept(acpt) <= 0) {
     fprintf(stderr, "Error in connection\n");
     ERR_print_errors_fp(stderr);
     exit(1);
 }

 /* We only want one connection so remove and free accept BIO */
 sbio = BIO_pop(acpt);
 BIO_free_all(acpt);

 if (BIO_do_handshake(sbio) <= 0) {
     fprintf(stderr, "Error in SSL handshake\n");
     ERR_print_errors_fp(stderr);
     exit(1);
 }

 BIO_puts(sbio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
 BIO_puts(sbio, "\r\nConnection Established\r\nRequest headers:\r\n");
 BIO_puts(sbio, "--------------------------------------------------\r\n");

 for ( ; ; ) {
     len = BIO_gets(sbio, tmpbuf, 1024);
     if (len <= 0)
         break;
     BIO_write(sbio, tmpbuf, len);
     BIO_write(out, tmpbuf, len);
     /* Look for blank line signifying end of headers*/
     if (tmpbuf[0] == '\r' || tmpbuf[0] == '\n')
         break;
 }

 BIO_puts(sbio, "--------------------------------------------------\r\n");
 BIO_puts(sbio, "\r\n");
 BIO_flush(sbio);
 BIO_free_all(sbio);

 }

