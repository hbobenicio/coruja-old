/**
 * @see https://gist.github.com/cseelye/adcd900768ff61f697e603fd41c67625
 */
#include <time.h>
#include <assert.h>
#include <stdbool.h>
#include <threads.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

// #include <sqlite3.h>

#include <coruja/ansi.h>
#include <coruja/coruja.h>
#include <coruja/log.h>

static int on_check_thread_start(void* thread_context);
int on_verify(int preverify_ok, X509_STORE_CTX *x509_ctx);

void coruja_setup() {
    coruja_log_info("%s", OPENSSL_VERSION_TEXT);

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
}

void coruja_cleanup() {
    // noop atm
}

int coruja_check_urls(const char** urls, size_t urls_length) {
    thrd_t threads[urls_length];

    // Create worker threads to do the check
    for (size_t i = 0; i < urls_length; i++) {
        coruja_log_info("checking address '%s'...", urls[i]);
        if (thrd_create(&threads[i], on_check_thread_start, (void*) urls[i]) != thrd_success) {
            fprintf(stderr, "error: check: could not start working thread\n");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for them to complete (not handling their return values atm)
    for (size_t i = 0; i < urls_length; i++) {
        int thread_rc;
        if (thrd_join(threads[i], &thread_rc) != thrd_success) {
            fprintf(stderr, "error: check: could not start working thread\n");
            exit(EXIT_FAILURE);
        }
    }

    return EXIT_SUCCESS;
}

int coruja_parse_cert(const char *crt, size_t crt_size) {
    // TODO RAII - BIO, X509, etc
    BIO *buf = BIO_new_mem_buf(crt, (int)crt_size);
    if (!buf)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    // Create an openssl certificate from the BIO
    X509 *x509 = PEM_read_bio_X509_AUX(buf, NULL, NULL, NULL);
    if (!x509)
    {
        ERR_print_errors_fp(stderr);

        BIO_free(buf);
        return EXIT_FAILURE;
    }

    // The returned value is an internal pointer which MUST NOT be freed
    // @see https://www.openssl.org/docs/man1.1.0/man3/X509_get_subject_name.html
    X509_NAME *subject_name = X509_get_subject_name(x509);
    printf("Subject: ");
    X509_NAME_print_ex_fp(stdout, subject_name, 0, 0);
    puts("");

    // The returned value is an internal pointer which MUST NOT be freed
    // @see https://www.openssl.org/docs/man1.1.1/man3/X509_get0_notBefore.html
    // @see https://www.openssl.org/docs/man1.1.1/man3/X509_get0_notAfter.html
    const ASN1_TIME *not_before = X509_get0_notBefore(x509);
    const ASN1_TIME *not_after = X509_get0_notAfter(x509);
    const ASN1_INTEGER *serial_number = X509_get0_serialNumber(x509);

    BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    assert(bio_stdout != NULL);

    // @see https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_print.html
    printf("Not Before: ");
    int rc = ASN1_TIME_print(bio_stdout, not_before);
    printf("\nNot After: ");
    rc = ASN1_TIME_print(bio_stdout, not_after);
    puts("");

    // now's epoch time
    time_t now = time(NULL);
    //struct tm* tm_now = localtime(&now);
    int before_cmp = ASN1_TIME_cmp_time_t(not_before, now); // ok if -1
    int after_cmp = ASN1_TIME_cmp_time_t(not_after, now);   // ok if 1
    bool not_expired = before_cmp < 0 && after_cmp > 0;

    printf("before_cmp: %d\n", before_cmp);
    printf("after_cmp: %d\n", after_cmp);
    printf("not_expired: %d\n", not_expired);
    // TODO handle rc's

    // sqlite3 *db = NULL;
    // rc = sqlite3_open("data.db", &db);
    // if (rc) {
    //     fprintf(stderr, "error: cannot open database: %s\n", sqlite3_errmsg(db));
    //     sqlite3_close(db);
    // }

    BIO_free(bio_stdout);    
    X509_free(x509);
    BIO_free(buf);

    return EXIT_SUCCESS;
}

static int on_check_thread_start(void* thread_context) {
    const char* address = (const char*) thread_context;
    // TODO split this address if port is also defined

    // Setup ssl context
    // SSL_CONF_CTX *context_config = SSL_CONF_CTX_new();
    // SSL_CONF_CTX_set_flags(context_config, SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE);
    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (!context) {
        coruja_log_error("check: openssl: could not allocate a new SSL_CTX");
        return 1;
    }
    SSL_CTX_set_verify(context, /*SSL_VERIFY_NONE*/ SSL_VERIFY_PEER, on_verify);
    SSL_CTX_set_verify_depth(context, 10);

    BIO* ssl_bio = BIO_new_ssl_connect(context);
    if (!ssl_bio) {
        coruja_log_error("check: openssl: could not allocate a new ssl connect BIO");
        SSL_CTX_free(context);
        return 1;
    }
    
    // TODO discover how to disable server certificate validation
    //SSL* ssl = SSL_new(context);
    SSL* ssl = NULL;
    // Borrowed reference. Do not free it.
    BIO_get_ssl(ssl_bio, &ssl);
    if (!ssl) {
        coruja_log_error("check: openssl: could not get ssl session reference");
        BIO_free_all(ssl_bio);
        SSL_CTX_free(context);
        return 1;
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    int rc;
    // if (!(rc = SSL_set1_host(ssl, address))) {
    //     coruja_log_error("check: openssl[%d]: could not set host for address '%s'", rc, address);
    //     SSL_free(ssl);
    //     SSL_CTX_free(context);
    //     //SSL_CONF_CTX_free(context_config);
    //     return rc;
    // }

    long wat = BIO_set_conn_hostname(ssl_bio, address);

    if(BIO_do_handshake(ssl_bio) <= 0) {
        coruja_log_error("check: openssl: could not establish TLS connection");
        //ERR_print_errors_fp(stderr);

        BIO_free_all(ssl_bio);
        SSL_CTX_free(context);
        return 1;
    }

    // coruja_log_info("conectando com o servidor...");
    // if (!(rc = SSL_connect(ssl))) {
    //     coruja_log_error("check: openssl[%d]: could not connect to address '%s'", rc, address);
    //     BIO_free(ssl_bio);
    //     //SSL_free(ssl);
    //     SSL_CTX_free(context);
    //     //SSL_CONF_CTX_free(context_config);
    //     return rc;
    // }
    // coruja_log_info("conectado com sucesso.");

    /* Could examine ssl here to get connection info */
    // BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    // for(;;) {      
    //         len = BIO_read(sbio, tmpbuf, 1024);
    //         if(len <= 0) break;
    //         BIO_write(out, tmpbuf, len);
    // }

    STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain == NULL) {
        coruja_log_warn("check: openssl: could not get peer cert chain for address '%s'", address);
        BIO_free_all(ssl_bio);
        //SSL_free(ssl);
        SSL_CTX_free(context);
        //SSL_CONF_CTX_free(context_config);
        return 1;
    }

    printf(CORUJA_BRIGHT_CYAN_BOLD "%s:" CORUJA_ANSI_GFX_RESET "\n", address);
    for (X509* cert = sk_X509_pop(cert_chain); cert != NULL; cert = sk_X509_pop(cert_chain)) {
        X509_NAME* subject_name = X509_get_subject_name(cert);
        printf(CORUJA_BRIGHT_CYAN_BOLD "  Subject: " CORUJA_ANSI_GFX_RESET);
        X509_NAME_print_ex_fp(stdout, subject_name, 0, 0);
        puts("");

        const ASN1_TIME *not_before = X509_get0_notBefore(cert);
        const ASN1_TIME *not_after = X509_get0_notAfter(cert);

        BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

        // @see https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_print.html
        printf(CORUJA_BRIGHT_CYAN_BOLD "    Not Before: " CORUJA_ANSI_GFX_RESET);
        int rc = ASN1_TIME_print(bio_stdout, not_before);
        printf(CORUJA_BRIGHT_CYAN_BOLD "\n    Not After: " CORUJA_ANSI_GFX_RESET);
        rc = ASN1_TIME_print(bio_stdout, not_after);
        puts("");

        // now's epoch time
        time_t now = time(NULL);
        ASN1_TIME now_asn1;
        if(ASN1_TIME_set(&now_asn1, now) == NULL) {
            coruja_log_error("check: openssl: could not create ASN1_TIME from now");
            BIO_free_all(bio_stdout);
            continue;
        }

        //struct tm* tm_now = localtime(&now);
        int before_cmp = ASN1_TIME_cmp_time_t(not_before, now); // ok if -1
        int after_cmp = ASN1_TIME_cmp_time_t(not_after, now);   // ok if 1
        bool not_expired = before_cmp < 0 && after_cmp > 0;

        int days_until_expiration;
        int secs_until_expiration;
        if (!ASN1_TIME_diff(&days_until_expiration, &secs_until_expiration, &now_asn1, not_after)) {
            coruja_log_error("check: openssl: could not calculate time diff from now until expiration");
            BIO_free_all(bio_stdout);
            continue;
        }

        // TODO Make color ranges!
        if (days_until_expiration < 2 * 30) {
            printf(CORUJA_BRIGHT_CYAN_BOLD "    Expires in: " CORUJA_BRIGHT_RED_BOLD "%d" CORUJA_ANSI_GFX_RESET "\n", days_until_expiration);
        } else if (days_until_expiration < 4 * 30) {
            printf(CORUJA_BRIGHT_CYAN_BOLD "    Expires in: " CORUJA_BRIGHT_YELLOW_BOLD "%d" CORUJA_ANSI_GFX_RESET "\n", days_until_expiration);
        } else {
            printf(CORUJA_BRIGHT_CYAN_BOLD "    Expires in: " CORUJA_BRIGHT_GREEN_BOLD "%d" CORUJA_ANSI_GFX_RESET "\n", days_until_expiration);
        }

        if (not_expired) {
            puts("    ✅ Not Expired!");
        } else {
            puts("    ❌ Expired!");
        }


        BIO_free_all(bio_stdout);

        // TODO Count number of days until expiration
    }

    //SSL_shutdown(ssl);

    // From this stack, pass it to coruja_parse_cert maybe... (or create another method)

    // if (SSL_get_verify_result(ssl) == X509_V_OK) {
    //   const char *peername = SSL_get0_peername(ssl);

    //   if (peername != NULL) {
    //       /* Name checks were in scope and matched the peername */
    //   }
    // }

    BIO_free_all(ssl_bio);
    //SSL_free(ssl);
    SSL_CTX_free(context);
    //SSL_CONF_CTX_free(context_config);

    return 0;
}

int on_verify(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    return 1;
}
