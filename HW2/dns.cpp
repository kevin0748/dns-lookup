#include "pch.h"

bool makeDNSquestionA(char* buf, const char* host) {
	const char* left, *right;
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

bool makeDNSquestionPtr(char* buf, DWORD IP, char* addr, int addrSize) {
	snprintf(addr,addrSize, "%d.%d.%d.%d.in-addr.arpa",
		(IP & 0xFF000000) >> 24,
		(IP & 0x00FF0000) >> 16,
		(IP & 0x0000FF00) >> 8,
		IP & 0x000000FF
	);

	return makeDNSquestionA(buf, addr);
}

/*
* getRRName
* 
* output:
*  u_int* skipSize
*/
string DNS::getRRName(const char *buf, int bufSize, int startIdx, u_int* skipSize) {
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

const char* DNS::getQueryTypeName(u_short type) {
	if (queryTypeMap.find(type) != queryTypeMap.end()) {
		return queryTypeMap[type];
	}
	
	return NULL;
}


bool DNS::getRR(const char* buf, int bufSize, char*& cursor) {
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

		printf("\t%s %s %s TTL = %d\n",
			rrName.c_str(), // name
			getQueryTypeName(qType), // type
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

		printf("\t%s %s %s TTL = %d\n",
			rrName.c_str(), // name
			getQueryTypeName(qType), // type
			rrDataName.c_str(),// rData
			ntohl(fr->TTL)// ttl
		);

		return true;
	}
	else {
		printf("dns type %d not implemented\n", qType);
		cursor += dataLen;
		return true;
	}
}

bool DNS::parseResponse(u_short sentTxid, char* buf, int bufSize) {
	FixedDNSheader* fdh = (FixedDNSheader*)buf;
	char* cursor = (char*)(fdh + 1);
	
	/*
	for (int i = cursor - buf; i < bufSize; ++i) {
		printf("[%d] %02hhX\t", i, buf[i]);
	}
	*/

	u_short txid = ntohs(fdh->TXID);
	u_short flags = ntohs(fdh->flags);
	u_short nQuestions = ntohs(fdh->nQuestions);
	u_short nAnswers = ntohs(fdh->nAnswers);
	u_short nAuthority = ntohs(fdh->nAuthority);
	u_short nAdditional = ntohs(fdh->nAdditional);
	u_short rCode = flags & 15;

	// handle mismatch txid
	if (txid != sentTxid) {
		printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n", sentTxid, txid);
		return false;
	}

	printf("  TXID: 0x%.4X, flags 0x%.4X, questions %d, answers %d, authority %d, additional %d\n", txid, flags, nQuestions, nAnswers, nAuthority, nAdditional);
	if (rCode == DNS_OK) {
		printf("  succeeded with Rcode = 0\n");
	}
	else {
		printf("  failed with Rcode = %d\n", rCode);
		return false;
	}
	

	// questions
	if (nQuestions > 0) {
		printf("  ------------ [questions] ----------\n");
		//printf("nQuestions: %d\n", nQuestions);
		for (int i = 0; i < nQuestions; ++i) {
			u_int nameSkipSize;

			string rrName = getRRName(buf, bufSize, cursor - buf, &nameSkipSize);
			if (rrName == "") {
				return false;
			}

			QueryHeader* qh = (QueryHeader*)(cursor + nameSkipSize);
			cursor += nameSkipSize + sizeof(QueryHeader);

			printf("\t%s type %d class %d\n",
				rrName.c_str(),
				ntohs( qh->qType), 
				ntohs(qh->qClass));
		}
	}

	// answers
	if (nAnswers > 0) {
		printf("  ------------ [answers] ----------\n");
		//printf("nAnswers: %d\n", nAnswers);
		for (int i = 0; i < nAnswers; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}


	// authority
	if (nAuthority > 0) {
		printf("  ------------ [authority] ----------\n");
		//printf("nAuthority: %d\n", nAuthority);
		for (int i = 0; i < nAuthority; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}

	// additional
	if (nAdditional > 0) {
		printf("  ------------ [additional] ----------\n");
		//printf("nAdditional: %d\n", nAdditional);
		for (int i = 0; i < nAdditional; ++i) {
			getRR(buf, bufSize, cursor);
		}
	}


	return true;
}


DNS::DNS() {
	TXID = 1;

	queryTypeMap[DNS_A] = "A";
	queryTypeMap[DNS_NS] = "NS";
	queryTypeMap[DNS_CNAME] = "CNAME";
	queryTypeMap[DNS_PTR] = "PTR";
}

bool DNS::query(const char* lookupAddr, const char* server) {
	int pkg_size = sizeof(FixedDNSheader) + sizeof(QueryHeader);
	char* buf = NULL;

	u_short txid = TXID++;
	u_short qType;

	DWORD IP = inet_addr(lookupAddr);
	if (IP == INADDR_NONE) { // A Query
		qType = DNS_A;
		pkg_size += strlen(lookupAddr) + 2;
	}
	else { // Ptr Query
		qType = DNS_PTR;
		int addrSize = strlen(lookupAddr) + 15;
		pkg_size += addrSize;
	}

	buf = new char[pkg_size];
	FixedDNSheader* fdh = (FixedDNSheader*)buf;
	QueryHeader* qh = (QueryHeader*)(buf + pkg_size - sizeof(QueryHeader));

	fdh->TXID = htons(txid);
	fdh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	fdh->nQuestions = htons(1);
	fdh->nAnswers = 0;
	fdh->nAuthority = 0;
	fdh->nAdditional = 0;

	qh->qType = htons(qType);
	qh->qClass = htons(DNS_INET);

	printf(" Lookup\t: %s\n", lookupAddr);

	if (qType == DNS_A) { // A Query
		makeDNSquestionA((char*)(fdh + 1), lookupAddr);
		printf(" Query\t: %s, type %d, TXID 0x%.4X\n", lookupAddr, qType, txid);
	}
	else { // Ptr Query
		char* addr = new char[512];
		makeDNSquestionPtr((char*)(fdh + 1), IP,addr, 512+1);
		printf(" Query\t: %s, type %d, TXID 0x%.4X\n", addr, qType, txid);
		delete addr;
	}

	printf(" Server\t: %s\n", server);
	printf(" ********************************\n");
	
	// socket
	Socket sock = Socket();
	int count = 0;
	bool readOk = false;
	while (count < MAX_ATTEMPTS) {
		printf(" Attempt %d with %d bytes... ", count, pkg_size);
		clock_t timer = clock();

		if (sock.Send(server, buf, pkg_size) == false) {
			continue;
		}

		int readResult = sock.Read(server);
		if (readResult == SOCK_OK) {
			readOk = true;
			timer = clock() - timer;
			printf("response in %d ms with %d bytes\n", 1000 * timer / CLOCKS_PER_SEC, sock.bufSize);
			break;
		}
		else if (readResult == ERR_SOCK_TIMEOUT) {
			timer = clock() - timer;
			printf("timeout in %d ms\n", 1000 * timer / CLOCKS_PER_SEC);
		}
		else if (readResult == ERR_SOCK_ERROR) {
			break;
		}
		
		count++;
	}
	if (!readOk) {
		return false;
	}

	parseResponse(txid, sock.buf, sock.bufSize);

	delete buf;
	return true;
}

