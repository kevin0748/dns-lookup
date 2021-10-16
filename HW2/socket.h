#pragma once

#define INITIAL_BUF_SIZE 512

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
    bool Read(const char* ip);
};

