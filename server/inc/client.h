#pragma once

#include <string>
#include <iostream>
#include <future>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Client
{

public:
    Client(int socket);
    Client(const Client &) = delete;
    ~Client();

private:
    SSL_CTX *CreateContext();

    SSL *ssl;
    SSL_CTX *ctx;
    int client;
    std::future<void> f;
};