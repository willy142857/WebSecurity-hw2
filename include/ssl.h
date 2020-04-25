#include <exception>
#include <iostream>
#include <string_view>
#include <filesystem>

#include <openssl/ssl.h>
#include "exception.h"

namespace fs = std::filesystem;

class Certificate
{
public:
    Certificate(X509* cert)
    {
        this->cert = cert;
    }

    std::string getSubjectName()
    {
        auto str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::string ret(str);
        delete[] str;

        return ret;
    }

    std::string getIssuerName()
    {
        auto str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::string ret(str);
        delete[] str;

        return ret;
    }

    bool isEmpty() { return !cert; }

    ~Certificate() { X509_free(cert); }
private:
    X509* cert;
};

class SSLCtx 
{
public:
    SSLCtx(const std::string& path)
        :sslPath(path)
    {
        SSL_library_init();
        SSL_load_error_strings();

        createCtx();
    }

    void configure(std::string_view cert="host.crt", std::string_view key="host.key", std::string_view cacert="ca.crt")
    {
        fs::current_path(sslPath);

        SSL_CTX_set_ecdh_auto(ctx, 1);
        if (SSL_CTX_use_certificate_file(ctx, cert.data(), SSL_FILETYPE_PEM) <= 0)
            throw SSLException("certificate not found");
    
        if (SSL_CTX_use_PrivateKey_file(ctx, key.data(), SSL_FILETYPE_PEM) <= 0)
            throw SSLException("key not found");

        if (!SSL_CTX_check_private_key(ctx))
            throw SSLException("Private key does not match the certificate public key");

        /* Load the RSA CA certificate into the SSL_CTX structure */
        if (!SSL_CTX_load_verify_locations(ctx, cacert.data(), NULL))
            throw SSLException();

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 1); 
    }

    SSL_CTX* getUnderlying() const 
    {
        return ctx;
    }
    
    ~SSLCtx() 
    {
        SSL_CTX_free(ctx);
    }

private:
    std::string sslPath;
    SSL_CTX* ctx;

    void createCtx() {
        auto method = SSLv23_method();

        ctx = SSL_CTX_new(method);
        if (!ctx) 
	        throw SSLException("Unable to create SSL context");
    }

};

class SSLConnection
{
public:
    SSLConnection(SSL_CTX* ctx, int sock)
    {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
    }

    void accept()
    {
        if (SSL_accept(ssl) < 0)
            throw SSLException("SSL accept error");
    }

    void connect()
    {
        if (SSL_connect(ssl) < 0)
            throw SSLException("SSL connect error");
    }

    int read(char* buf, int size)
    {
        auto s = SSL_read(ssl, buf, size);

        if (s < 0)
            throw SSLException("SSL read error");
        
        return s;
    }

    int write(const char* buf, int size)
    {
        auto s = SSL_write(ssl, buf, size);

        if (s < 0)
            throw SSLException("SSL write error");
        
        return s;
    }

    void shutdown()
    {
        if (SSL_shutdown(ssl))
            throw "SSL shutdown error";
    }

    Certificate getPeerCertificate()
    {
        return Certificate(SSL_get_peer_certificate(ssl));
    }

    const char* getCipher() const
    {
        return SSL_get_cipher(ssl);
    }

    ~SSLConnection()
    {
        SSL_free(ssl);
    }

private:
    SSL* ssl;
};

