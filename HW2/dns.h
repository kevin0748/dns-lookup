#pragma once
#include<windows.h>

using namespace std;

/* DNS query types */
#define DNS_A       1    /* name->IP */
#define DNS_NS      2    /* name server */
#define DNS_CNAME   5    /* canonical name */    
#define DNS_PTR    12    /* IP->name */  
#define DNS_HINFO  13    /* host info/SOA */    
#define DNS_MX     15    /* mail exchange */ 
#define DNS_AXFR  252    /* request for zone transfer */     
#define DNS_ANY   255    /* all records */  

/* query classes */
#define DNS_INET 1

/* flags */
#define DNS_QUERY	  (0 << 15)  /* 0 = query; 1 = response */
#define DNS_RESPONSE  (1 << 15)
#define DNS_STDQUERY  (0 << 11)  /* opcode - 4 bits */
#define DNS_AA	      (1 << 10)  /* authoritative answer */
#define DNS_TC	      (1<<9)     /* truncated */
#define DNS_RD	      (1<<8)     /* recursion desired */
#define DNS_RA	      (1<<7)     /* recursion available */

/* result */
#define DNS_OK         0  /* success */
#define DNS_FORMAT     1  /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2  /* can�t find authority nameserver */
#define DNS_ERROR      3  /* no DNS entry */
#define DNS_NOTIMPL    4  /* not implemented */
#define DNS_REFUSED    5  /* server refused the query */

#pragma pack(push,1)  // sets struct padding/alignment to 1 byte
class QueryHeader {
public:
    USHORT qType;
    USHORT qClass;
};


class FixedDNSheader {
public:
    USHORT TXID;
    USHORT flags;
    USHORT nQuestions;
    USHORT nAnswers;
    USHORT nAuthority;
    USHORT nAdditional;
    //...
};
#pragma pack(pop)  // restores old packing

#define MAX_DNS_SIZE 512  // largest valid UDP packet
#pragma pack(push,1)  // sets struct padding/alignment to 1 byte
class FixedRR {
public:
    u_short qType;
    u_short qClass;
    u_int TTL;
    u_short len;
    // ...
};
#pragma pack(pop)  // restores old packing

#define MAX_ATTEMPTS 3

#define DNS_FIXED_HEADER_SIZE  12

#define DNS_OK 0
#define ERR_DNS_UNDEFINED 1
#define ERR_DNS_BEYOND_PKT 2
#define ERR_DNS_JUMP_TO_FIXED_HEADER 3
#define ERR_DNS_INVALID_JUMP_OFFSET 4
#define ERR_DNS_RRVALUE_BEYOND_PKT 5
#define ERR_DNS_RRNAME_BEYOND_PKT 6
#define ERR_DNS_INVALID_RR_HEADER 7
#define ERR_DNS_JUMP_LOOP 8

class DNS {
private:
    USHORT TXID;
    unordered_map<u_short, const char*> queryTypeMap;
    unordered_map<u_short, bool> visited; // (visited, solved)

public:
    DNS();
    bool query(const char* lookupAddr, const char* server);
    bool parseResponse(u_short txid, char* buf, int bufSize);
    int getRRName(const char* buf, int bufSize, int startIdx, u_int* skipSize, string& rrName);
    int getRR(const char* buf, int bufSize, char*& cursor);
    const char* getQueryTypeName(u_short type);
};

