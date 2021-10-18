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

/*
* getRRName
* 
* output:
*  u_int* skipSize
*/
string getRRName(const char *buf, int bufSize, int startIdx, u_int* skipSize) {
	string rrName;
	int i = 0;
	int curPos = startIdx;
	u_char cursor = buf[curPos];
	while (cursor) {
		// check compressed
		if (cursor >= 0xC0) {
			if (curPos + 1 >= bufSize) {
				printf("name size exceed buf size\n");
				return "";
			}

			int off = ((buf[curPos] & 0x3F) << 8) + (u_char)buf[curPos + 1];
			u_int dummySkipSize;
			string compressRRName = getRRName(buf, bufSize, off, &dummySkipSize);

			if (rrName.size() > 0) {
				rrName += '.';
			}
			rrName += compressRRName;
			*skipSize = curPos - startIdx + 2;
			return rrName;
		}

		curPos++; // it's not compressed, move curPos forward
		int len = (int)cursor;
		if (curPos + len >= bufSize) {
			printf("name size exceed buf size\n");
			return "";
		}

		if (i != 0) {
			rrName += ".";
		}

		string name(buf + curPos, len);
		//memcpy(name + i, buf+curPos, len);
		rrName += name;
		i += len;
		curPos += len;
		cursor = buf[curPos];
	}

	//name[i] = NULL;
	*skipSize = curPos - startIdx + 1;
	return rrName;
}

bool getRRData(const char* buf, int bufSize, int start, int dataSize, char* data) {
	if (start + dataSize >= bufSize) {
		printf("getRRData: exceed bufSize\n");
		return false;
	}

	memcpy(data, buf + start, dataSize);
	data[dataSize] = NULL;
	return true;
}

bool getRR(const char* buf, int bufSize, char*& cursor) {
	u_int nameSkipSize;

	// TODO: fix return
	string rrName = getRRName(buf, bufSize, cursor - buf, &nameSkipSize);
	if (rrName == "") {
		return false;
	}

	FixedRR* fr = (FixedRR*)(cursor + nameSkipSize);
	cursor += nameSkipSize + sizeof(FixedRR);

	int dataLen = ntohs(fr->len);

	u_short qType = ntohs(fr->qType);
	if (qType == DNS_A) {
		char* rrData = new char[dataLen + 1];
		if (getRRData(buf, bufSize, cursor - buf, dataLen, rrData) == false) {
			return false;
		}
		cursor += dataLen;

		in_addr addr;
		memcpy((char*)&(addr), rrData, dataLen);
		delete rrData;

		printf("%s %d %s TTL = %d\n",
			rrName.c_str(), // name
			qType, // type
			inet_ntoa(addr),// rData
			ntohl(fr->TTL)// ttl
		);

		return true;
	}
	else if (qType == DNS_NS || qType == DNS_CNAME || qType == DNS_PTR) {
		u_int dataSkipSize;
		string rrDataName = getRRName(buf, bufSize, cursor - buf, &dataSkipSize);
		if (rrDataName == "") {
			return false;
		}
		cursor += dataLen;

		printf("%s %d %s TTL = %d\n",
			rrName.c_str(), // name
			qType, // type
			rrDataName.c_str(),// rData
			ntohl(fr->TTL)// ttl
		);

		return true;
	}
	else {
		printf("dns type not implemented\n");
		return false;
	}
}

bool parseResponse(char* buf, int bufSize) {
	FixedDNSheader* fdh = (FixedDNSheader*)buf;
	char* cursor = (char*)(fdh + 1);
	
	
	for (int i = cursor - buf; i < bufSize; ++i) {
		printf("[%d] %02hhX\t", i, buf[i]);
	}

	u_short nQuestions = ntohs(fdh->nQuestions);
	u_short nAnswers = ntohs(fdh->nAnswers);
	u_short nAuthority = ntohs(fdh->nAuthority);
	u_short nAdditional = ntohs(fdh->nAdditional);
	
	printf("TXID: %.4x\n", fdh->TXID);
	printf("Flags: %x\n", fdh->flags);


	// questions
	if (nQuestions > 0) {
		printf("---------- [questions] ----------\n");
		printf("nQuestions: %d\n", nQuestions);
		for (int i = 0; i < nQuestions; ++i) {
			u_int nameSkipSize;

			string rrName = getRRName(buf, bufSize, cursor - buf, &nameSkipSize);
			if (rrName == "") {
				return false;
			}

			QueryHeader* qh = (QueryHeader*)(cursor + nameSkipSize);
			cursor += nameSkipSize + sizeof(QueryHeader);

			printf("%s type %d class %d\n",
				rrName.c_str(),
				ntohs( qh->qType), 
				ntohs(qh->qClass));
		}
	}

	// answers
	if (nAnswers > 0) {
		printf("---------- [answers] ----------\n");
		printf("nAnswers: %d\n", nAnswers);
		for (int i = 0; i < nAnswers; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}


	// authority
	if (nAuthority > 0) {
		printf("---------- [authority] ----------\n");
		printf("nAuthority: %d\n", nAuthority);
		for (int i = 0; i < nAuthority; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}

	// additional
	if (nAdditional > 0) {
		printf("---------- [additional] ----------\n");
		printf("nAdditional: %d\n", nAdditional);
		for (int i = 0; i < nAdditional; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}


	return true;
}



bool query() {
	char server[] = "128.194.135.85";
	char host[] = "akamai.com";

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

	parseResponse(sock.buf, sock.bufSize);


	delete buf;


	return true;
}

