#include "pch.h"

bool makeDNSquestion(char* buf, char* host) {
	char* left, *right;
	int i = 0;

	left = host;
	right = strchr(host, '.');
	while (right != NULL) {
		int word_size = right - left;
		buf[i++] = word_size;
		memcpy(buf+i, left, word_size);
		i += word_size;

		left = right + 1;
		right = strchr(left, '.');
	}

	if (left != NULL) {
		right = strchr(left, '\0');
		int word_size = right - left;
		buf[i++] = word_size;
		memcpy(buf + i, left, word_size);
		i += word_size;
	}

	buf[i] = 0;    // last word NULL-terminated
	return true;
}

bool query() {
	char server[] = "8.8.8.8";
	char host[] = "www.google.com";

	int pkt_size = strlen(host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);

	char* buf = new char[pkt_size];

	FixedDNSheader* fdh = (FixedDNSheader*) buf;
	QueryHeader* qh = (QueryHeader*)(buf + pkt_size - sizeof(QueryHeader));

	fdh->TXID = 0xABCD;
	fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	fdh->nQuestions = htons(1);
	fdh->nAnswers = 0;
	fdh->nAuthority = 0;
	fdh->nAdditional = 0;
	
	qh->qType = htons(DNS_A);
	qh->qClass = htons(DNS_INET);

	makeDNSquestion((char*)(fdh + 1), host);



	// socket
	Socket sock = Socket();
	if (sock.Send(server, buf, pkt_size) == false) {
		return false;
	}

	if (sock.Read(server) == false) {
		return false;
	}

	FixedDNSheader* fdh2 = (FixedDNSheader*)sock.buf;
	char* payload = (char*)(fdh2 + 1);
	for (int i = payload - sock.buf; i < sock.bufSize; ++i) {
		printf("%x ", sock.buf[i]);
	}

	delete buf;


	return true;
}