#pragma once

#define INITIAL_BUF_SIZE 512

#define SOCK_OK 0
#define ERR_SOCK_UNDEFINED 1
#define ERR_SOCK_TIMEOUT 2
#define ERR_SOCK_ERROR 3

class Socket
{
public:
    SOCKET sock;       // socket handle
    char* buf;         // current buffer
    int bufSize;
    int allocatedSize; // bytes allocated for buf

    Socket();
    ~Socket();

    bool Send(const char* ip, const char* msg, int msgLen);
    int Read(const char* ip);
};

