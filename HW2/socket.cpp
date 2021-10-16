#include "pch.h"

Socket::Socket()
{
    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        printf("WSAStartup error %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    // open a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET)
    {
        printf("socket() generated error %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    // bind socket
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("socket bind error %d\n", WSAGetLastError());
        return;
    }

    // create this buffer once, then possibly reuse for multiple connections in Part 3
    buf = (char*)malloc(INITIAL_BUF_SIZE);
    allocatedSize = INITIAL_BUF_SIZE;
}

Socket::~Socket() {
    delete buf;

    // close the socket to this server; open again for the next one
    closesocket(sock);

    // call cleanup when done with everything and ready to exit program
    WSACleanup();
}

bool Socket::Send(const char* ip, const char* msg, int msgLen) {
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(ip); // server’s IP
    remote.sin_port = htons(53); // DNS port on server
    if (sendto(sock, msg, msgLen, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
        printf("socket send error %d\n", WSAGetLastError());
        return false;
    }
       
    printf("socket send success\n");
    return true;
}

bool Socket::Read(const char* ip) {
    fd_set rfd;
    FD_ZERO(&rfd);
    FD_SET(sock, &rfd);
 
    int ret;
    int threshold = 10;

    // set timeout to 10 seconds
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;


    struct sockaddr_in respAddr;
    memset(&respAddr, 0, sizeof(respAddr));
    int resplen = sizeof(respAddr);

    ULONG reqAddr= inet_addr(ip);
    u_short reqPort = htons(53);

    // wait to see if socket has any data (see MSDN)
    if ((ret = select(0, &rfd, nullptr, nullptr, &timeout)) > 0)
    {
        int bytes = recvfrom(sock, buf, allocatedSize, 0, (sockaddr*)&respAddr, &resplen);
        if (bytes == SOCKET_ERROR) {
            printf("failed with %d on recv\n", WSAGetLastError());
            return false;
        }

        if (bytes == 0) {
            printf("empty response\n");
            return false;
        }

        // check if this packet match the query server
        if (respAddr.sin_addr.s_addr != reqAddr || respAddr.sin_port != reqPort) {
            printf("recv unmatched addr or port\n");
            return false;
        }

        bufSize = bytes;
        buf[bytes] = NULL;
        return true; 
    }
    else if (ret == 0) {
        // report timeout
        printf("recv: timeout\n");
        return false;
    }
    else {
        printf("recv error: %d\n", WSAGetLastError());
        return false;
    }
}
