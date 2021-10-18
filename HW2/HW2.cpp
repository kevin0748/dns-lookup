// HW2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("invalid argument.\n");
        printf("[Usage] HW2.exe $hostOrIP $dnsServer\n");
        exit(1);
    }

    char* server = argv[2];
    //char server[] = "128.194.135.82"; //custom
    //char server[] = "8.8.8.8";
    //char server[] = "127.0.0.1";
    //char server[] = "128.194.135.85";
    //char server[] = "128.194.135.11";
    
    char* host = argv[1];
    //char host[] = "165.91.22.70";
    //char host[] = "google.com";
    //char host[] = "random8.irl";
    //char host[] = "128.194.138.19";


    DNS dns = DNS();
    dns.query(host, server);
    
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
