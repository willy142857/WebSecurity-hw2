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
        fmt::print(fmt::fg(fmt::color::red), "Usage: server <port> <key_path>\n");
        return -1;
    }

    int port = std::atoi(argv[1]);
    std::string path(argv[2]);
    bool verifyClient = true; 
    /*----------------------------------------------------------------*/
    try {
        SSLCtx sslctx(path);
        sslctx.configure("host.crt", "host.key");
        auto ctx = sslctx.getUnderlying();

        /* ----------------------------------------------- */
        /* Set up a TCP socket */
        fmt::print(fmt::fg(fmt::color::azure), "server listen on port: {}\n", port);

        boost::asio::io_service io_service;
        tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), port));
        tcp::socket socket(io_service);
        acceptor.accept(socket);

        fmt::print(fmt::fg(fmt::color::yellow), "[New Connection]: {}:{}\n", 
            socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port());
    
        /* ----------------------------------------------- */
        /* TCP connection is ready. */
        /* A SSL structure is created */
        auto ssl = SSLConnection(ctx, socket.native_handle());
        ssl.accept();

        fmt::print(fmt::fg(fmt::color::antique_white), "SSL connection using {}\n", ssl.getCipher());
        
        /* Get the client's certificate (optional) */
        if (verifyClient) {
            auto cert = Certificate(ssl.getPeerCertificate());    
            if (!cert.isEmpty()) {
                fmt::print(fmt::fg(fmt::color::aqua), "Client certificate:\n");
            fmt::print(fmt::fg(fmt::color::aqua), "subject: {}\n", cert.getSubjectName());
            fmt::print(fmt::fg(fmt::color::aqua), "issuer: {}\n", cert.getIssuerName());
            }
            else {
                fmt::print(fmt::fg(fmt::color::indian_red), "The SSL client does not have certificate.\n");
            }
        }

        /*------- DATA EXCHANGE - Receive message and send reply. -------*/
        
        /* Receive data from the SSL client */
        char buf[4096];
        auto len = ssl.read(buf, sizeof(buf) - 1);
        buf[len] = '\0';
        fmt::print(fmt::fg(fmt::color::lime_green), "Received {} bytes from client: {}\n", len, buf);

        fmt::print(fmt::fg(fmt::color::spring_green), "Message to be sent to the client: ");
        std::string message;
        std::cin >> message;
        len = ssl.write(message.data(), message.size());

        /*--------------- SSL closure ---------------*/
        ssl.shutdown();
        fmt::print(fmt::fg(fmt::color::orange_red), "Connection closed\n");
    }
    catch (const std::exception& e) {
        fmt::print(fmt::fg(fmt::color::red) | fmt::emphasis::bold, "{}\n", e.what());
    }
}