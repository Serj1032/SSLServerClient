#include <exception>
#include <cstring>

#include "../inc/client.h"

using namespace std;

Client::Client(string ip, int port)
{
    int s;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (!s)
    {
        throw runtime_error("Error creating socket");
    }

    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip.c_str());
    sa.sin_port = htons(port);
    socklen_t socklen = sizeof(sa);

    if (connect(s, (struct sockaddr *)&sa, socklen))
    {
        throw runtime_error("Error connecting to server");
    }

    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *meth = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        LogSSL();
        throw runtime_error("Error creating SSL");
    }

    sock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, s);
    int err = SSL_connect(ssl);
    if (err <= 0)
    {
        LogSSL();
        throw runtime_error("Error creating SSL connection");
    }

    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
}

int Client::SendMessage(string msg)
{
    int len = SSL_write(ssl, msg.c_str(), msg.length());
    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        switch (err)
        {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
    return 0;
}

variant<string, int> Client::ReceiveMessage()
{
    int len = 100;
    char buff[1000000];
    do
    {
        len = SSL_read(ssl, buff, 100);
        buff[len] = 0;
        return string(buff);

        // std::cout << "Recv packet: " << buf << std::endl;
    } while (len > 0);
    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }
}

void Client::LogSSL()
{
    int err = ERR_get_error();
    while (err)
    {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;

        std::cout << str << std::endl;

        err = ERR_get_error();
    }
}