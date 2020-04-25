---
title: 'Web Security Hw2'
disqus: hackmd
---

Simple SSL Server
===

[TOC]

## 建置環境與使用說明

* Ubuntu 18.04
* g++ 7.5
* boost 1.65
* GNU Make 4.1
* CMake 3.10.2
* openssl 1.1

```bash
$ sudo apt -y update
$ sudo apt install -y g++ libboost-all-dev make cmake libssl-dev openssl
$ ./run.sh # build the project
$ ./genkey.sh # generate keys and certs to .key directory
$ ./build/bin/server 55688 .key # run server on port 55688
$ ./build/bin/client 55688 .key # run client on port 55688
```

重要程式碼
---

在程式一開始，會根據對應的key, cert, CA建立SSLCTX，並在最後設定需要檢查對方的certificate。openssl只提供C-style的function，為了開發上的方便，將用的的function包成class，由class掌管resource的life cycle，減少最後忘記free，以及盡量符合c++ RAII的風格。

```cpp
// include/ssl.h
// part of class SSLCtx
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
    // verify
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1); 
}
```

建立、管理SSL連線

```cpp
// include/ssl.h
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
```

使用c++ try/catch機制取代原本return -1的error handle，以期分離程式邏輯和錯誤處理，減少複雜度。

```cpp
//include/utility.h
//wrapper of openssl ERR_print_errors
std::string getOpenSSLError()
{
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    
    return ret;
}
    
// include/exception.h
class SSLException : public std::exception
{
public:
    SSLException(const char* s = "")
        :str(s) 
    {
        using namespace std::string_literals;
        str = str + "\n"s + getOpenSSLError();
    }

    virtual const char* what() const throw()
    {   
        return str.c_str();
    }

private:
    std::string str;
};
```

利用c++ fmt lib讓cmd有不同的顏色，看起來很炫泡。

```cpp
fmt::print(fmt::fg(fmt::color::azure), "server listen on port: {}\n", port);
```

剩餘的連線建立、send/receive message在程式碼都有註解，這裡就不說了。

設計架構與功能
---

### 架構


![](https://i.imgur.com/SXpYCSD.png)



### 功能

client連上對應的port後，會檢查server的certificate，同時也會傳自己的certificate給server驗證，待雙方都確認後，client和server能互送加密的訊息。

成果截圖
---

| Phase | Server | Client |
| -------- | -------- | -------- |
| 啟動server | ![1](https://i.imgur.com/txpQDcT.png) | null |
| client連線 | ![2](https://i.imgur.com/0SRpTsQ.png) | ![3](https://i.imgur.com/rlyCqwt.png) |
| client send | ![4](https://i.imgur.com/lxC8kXR.png) | ![5](https://i.imgur.com/hq23MoR.png) |
| server send | ![6](https://i.imgur.com/ciViwDT.png) | ![7](https://i.imgur.com/X9KqRvc.png) |

### 完整截圖

| ![8](https://i.imgur.com/ChjJNQY.png) | ![9](https://i.imgur.com/MmcU6My.png) |
| -------- | -------- | -------- |

### 從wireshark可看出封包經過加密，且protocal為TLSv1.3
![10](https://i.imgur.com/Hrkr2nb.png)

## 困難與心得

這次作業中，了解openssl使用花費不少時間，在建立csr時，最初沒有填寫CN(Common Name)導致之後產生的cert驗證失敗，踩了個雷。
而openssl/ssl.h提供的function我覺得用不慣，因此用class包裝起來，過程中也bug也不少，像是accept和connect寫錯導致client連不進來之類的。另外這次學習了cmake的撰寫，如何include library和路徑設定費了一番功夫。

總結，了解了openssl、cmake。
