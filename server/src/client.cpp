#include "client.h"

#include <unistd.h>

using namespace std;

Client::Client(int socket)
{
    ctx = CreateContext();

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    std::cout << "Waiting client connection..." << std::endl;

    client = accept(socket, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    f = async([this, socket]() {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        std::cout << "Client " << socket << " connected" << std::endl;

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {

            size_t size = 1000000;
            char buff[size];

            SSL_read(ssl, buff, size);
            std::cout << "Receive from client #" << socket << " : " << buff << std::endl;

            string reply = "Answer to client: " + string(buff);

            SSL_write(ssl, reply.c_str(), reply.length());
        }
    });
}

Client::~Client()
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);

    SSL_CTX_free(ctx);
}

SSL_CTX *Client::CreateContext()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}