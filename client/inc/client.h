#pragma once

#include <string>
#include <iostream>
#include <variant>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class Client
{
public:
    Client(std::string ip, int port);
    void LogSSL();
    int SendMessage(std::string msg);
    std::variant<std::string, int> ReceiveMessage();

private:
    SSL *ssl;
    int sock;
};