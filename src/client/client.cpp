#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <fmt/color.h>
#include <fmt/core.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "../../include/ssl.h"

using namespace::boost::asio;
using ip::tcp;

int main(int argc, char* argv[])
{
    if (argc != 3) {
        fmt::print(fmt::fg(fmt::color::red), "Usage: client <port> <key_path>\n");
        return -1;
    }

    int port = std::atoi(argv[1]);
    std::string path(argv[2]);
    try {
        SSLCtx sslctx(path);
        sslctx.configure("client.crt", "client.key");
        auto ctx = sslctx.getUnderlying();

        /* Set up a TCP socket */
        boost::asio::io_service io_service;
        tcp::socket socket(io_service);
        socket.connect(tcp::endpoint(ip::address::from_string("127.0.0.1"), port));    

        fmt::print(fmt::fg(fmt::color::yellow), "[Connect to server]: {}:{}\n", 
            socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port());
        /* ----------------------------------------------- */
        /* An SSL structure is created */
        auto ssl = SSLConnection(ctx, socket.native_handle());
        ssl.connect();
        /* Informational output (optional) */
        fmt::print(fmt::fg(fmt::color::antique_white), "SSL connection using {}\n", ssl.getCipher());
    
        /* Get the server's certificate */
        auto cert = Certificate(ssl.getPeerCertificate());    
        if (!cert.isEmpty()) {
            fmt::print(fmt::fg(fmt::color::aqua), "Server certificate:\n");
            fmt::print(fmt::fg(fmt::color::aqua), "subject: {}\n", cert.getSubjectName());
            fmt::print(fmt::fg(fmt::color::aqua), "issuer: {}\n", cert.getIssuerName());
        }
        else {
            fmt::print(fmt::fg(fmt::color::indian_red), "The SSL server does not have certificate.\n");
        }
    
        /*-------- DATA EXCHANGE - send message and receive reply. -------*/
        /* Send data to the SSL server */
        fmt::print(fmt::fg(fmt::color::spring_green), "Message to be sent to the server: ");
        std::string hello;
        std::cin >> hello;
        auto len = ssl.write(hello.data(), hello.size());  
    
        /* Receive data from the SSL server */
        char buf[4096];
        len = ssl.read(buf, sizeof(buf) - 1);
        buf[len] = '\0';
        fmt::print(fmt::fg(fmt::color::lime_green), "Received {} bytes from client: {}\n", len, buf);
    
        /*--------------- SSL closure ---------------*/
        ssl.shutdown();
        fmt::print(fmt::fg(fmt::color::orange_red), "Connection closed\n");
    }
    catch (const std::exception& e) {
        fmt::print(fmt::fg(fmt::color::red) | fmt::emphasis::bold, "{}\n", e.what());
    }  
}