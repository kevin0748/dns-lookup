# DNS Lookup

Program that issues recursive queries to DNS server and parses its responses. Use UDP to request and assemble DNS response which scattered across packets. Parse 
record type: `CNAME`, `A`, `NS`, and `PTR` response and generate DNS reports.

## Usage
```
./dns_lookup $TARGET $DNS_SERVER
```

## Runtime Example

DNS lookup
```
$ ./Debug/HW2.exe yahoo.com 8.8.8.8
 Lookup : yahoo.com
 Query  : yahoo.com, type 1, TXID 0x0001
 Server : 8.8.8.8
 ********************************
 Attempt 0 with 27 bytes... response in 32 ms with 123 bytes
  TXID: 0x0001, flags 0x8180, questions 1, answers 6, authority 0, additional 0
  succeeded with Rcode = 0
  ------------ [questions] ----------
        yahoo.com type 1 class 1
  ------------ [answers] ----------
        yahoo.com A 98.137.11.163 TTL = 412
        yahoo.com A 74.6.143.26 TTL = 412
        yahoo.com A 74.6.143.25 TTL = 412
        yahoo.com A 74.6.231.20 TTL = 412
        yahoo.com A 74.6.231.21 TTL = 412
        yahoo.com A 98.137.11.164 TTL = 412
```

Reverse IP Lookup
```
$ ./Debug/HW2.exe 98.137.11.163 8.8.8.8
 Lookup : 98.137.11.163
 Query  : 163.11.137.98.in-addr.arpa, type 12, TXID 0x0001
 Server : 8.8.8.8
 ********************************
 Attempt 0 with 44 bytes... response in 32 ms with 104 bytes
  TXID: 0x0001, flags 0x8180, questions 1, answers 1, authority 0, additional 0
  succeeded with Rcode = 0
  ------------ [questions] ----------
        163.11.137.98.in-addr.arpa type 12 class 1
  ------------ [answers] ----------
        163.11.137.98.in-addr.arpa PTR media-router-fp74.prod.media.vip.gq1.yahoo.com TTL = 325
```

DNS Lookup
```
$ ./Debug/HW2.exe www.google.com 8.8.8.8
 Lookup : www.google.com
 Query  : www.google.com, type 1, TXID 0x0001
 Server : 8.8.8.8
 ********************************
 Attempt 0 with 32 bytes... response in 34 ms with 128 bytes
  TXID: 0x0001, flags 0x8180, questions 1, answers 6, authority 0, additional 0
  succeeded with Rcode = 0
  ------------ [questions] ----------
        www.google.com type 1 class 1
  ------------ [answers] ----------
        www.google.com A 142.251.111.104 TTL = 300
        www.google.com A 142.251.111.105 TTL = 300
        www.google.com A 142.251.111.99 TTL = 300
        www.google.com A 142.251.111.103 TTL = 300
        www.google.com A 142.251.111.106 TTL = 300
        www.google.com A 142.251.111.147 TTL = 300
```

DNS Lookup with authority and additional fields
```
$ ./Debug/HW2.exe www.dhs.gov 128.194.135.84
Lookup  : www.dhs.gov
Query   : www.dhs.gov, type 1, TXID 0x0300
Server  : 128.194.135.84
********************************
Attempt 0 with 29 bytes... response in 6939 ms with 414 bytes
  TXID 0x0300 flags 0x8180 questions 1 answers 3 authority 8 additional 8
  succeeded with Rcode = 0
  ------------ [questions] ----------
        www.dhs.gov type 1 class 1
  ------------ [answers] ------------
         2
         www.dhs.gov CNAME www.dhs.gov.edgekey.net TTL = 3600
        www.dhs.gov.edgekey.net CNAME e6485.dscb.akamaiedge.net
        e6485.dscb.akamaiedge.net A 23.200.36.56 TTL = 20
  ------------ [authority] ----------
        dscb.akamaiedge.net NS n4dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n3dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n6dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n0dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n7dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n1dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n5dscb.akamaiedge.net TTL = 4000
        dscb.akamaiedge.net NS n2dscb.akamaiedge.net TTL = 4000
  ------------ [additional] ---------
        n0dscb.akamaiedge.net A 64.86.135.233 TTL = 4000
        n1dscb.akamaiedge.net A 88.221.81.194 TTL = 6000
        n2dscb.akamaiedge.net A 165.254.51.172 TTL = 8000
        n3dscb.akamaiedge.net A 23.5.164.32 TTL = 4000
        n4dscb.akamaiedge.net A 165.254.51.176 TTL = 6000
        n5dscb.akamaiedge.net A 165.254.51.167 TTL = 8000
        n6dscb.akamaiedge.net A 165.254.51.175 TTL = 4000
        n7dscb.akamaiedge.net A 165.254.51.169 TTL = 6000
```