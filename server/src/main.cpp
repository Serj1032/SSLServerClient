#include <iostream>
#include <cstring>
#include <list>
#include <memory>
#include <future>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client.h"

// https://github.com/darrenjs/openssl_examples
//https://wiki.openssl.org/index.php/Simple_TLS_Server

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

// void init_openssl()
// {
//     SSL_library_init();
//     SSL_load_error_strings();
//     OpenSSL_add_ssl_algorithms();
// }

// void cleanup_openssl()
// {
//     EVP_cleanup();
// }

// SSL_CTX *create_context()
// {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;

//     method = SSLv23_server_method();

//     ctx = SSL_CTX_new(method);
//     if (!ctx)
//     {
//         perror("Unable to create SSL context");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }

//     return ctx;
// }

// void configure_context(SSL_CTX *ctx)
// {
//     SSL_CTX_set_ecdh_auto(ctx, 1);

//     /* Set the key and cert */
//     if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
//     {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }

//     if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
//     {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
// }

int main(int argc, char **argv)
{
    //  init openssl
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // SSL_CTX *ctx = create_context();

    // configure_context(ctx);

    int sock = create_socket(1234);

    // std::list<std::future<void>> clients;
    std::list<std::shared_ptr<Client>> clients;

    /* Handle connections */
    while (1)
    {
        std::cout << "Create new socket connection" << std::endl;

        // auto f = std::async([sock]() {
        //     auto c = Client(sock);
        //     std::cout << "Client connection closed" << std::endl;
        // });

        // clients.push_back(move(f));
        clients.emplace_back(std::make_shared<Client>(sock));
        // clients.push_back(std::move(c));

        // struct sockaddr_in addr;
        // uint len = sizeof(addr);
        // SSL *ssl;
        // const char reply[] = "test\n";

        // std::cout << "Start accept socket client" << std::endl;

        // int client = accept(sock, (struct sockaddr *)&addr, &len);
        // if (client < 0)
        // {
        //     perror("Unable to accept");
        //     exit(EXIT_FAILURE);
        // }

        // ssl = SSL_new(ctx);
        // SSL_set_fd(ssl, client);

        // std::cout << "Start SSL_accept socket client" << std::endl;

        // if (SSL_accept(ssl) <= 0)
        // {
        //     ERR_print_errors_fp(stderr);
        // }
        // else
        // {
        //     size_t size = 1000000;
        //     char buff[size];
        //     SSL_read(ssl, buff, size);
        //     std::cout << "Receive from client: " << buff << std::endl;
        //     SSL_write(ssl, reply, strlen(reply));
        // }

        // std::cout << "Shutdown ssl connect" << std::endl;

        // SSL_shutdown(ssl);
        // SSL_free(ssl);
        // close(client);
    }

    close(sock);
    // SSL_CTX_free(ctx);

    // cleanup openssl
    EVP_cleanup();
}