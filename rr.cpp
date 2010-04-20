
#include "rr.hpp"

#include <iostream>
#include <arpa/inet.h>
#include <cstring>

#include "dns_packet.hpp"

using namespace std;

ResourceRecord::ResourceRecord()
{
    rrType = 0;
    rrClass = 0;
    ttl = 0;
    rdLen = 0;
}

ResourceRecord::ResourceRecord(const ResourceRecord& rr)
{
    *this = rr;
}

ResourceRecord::ResourceRecord(const string& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const string& rdata)
{
    uint32_t ip;
    
    this->rrDomain = convertDomain(rrDomain);
    this->rrType = htons(atoi(rrType.data()));
    this->rrClass = htons(atoi(rrClass.data()));
    this->ttl = htonl(atoi(ttl.data()));

    switch(this->rrType) {
        case 1:
            rdLen = 4;
            this->rdata = malloc(4);
            memcpy(this->rdata, &ip, 4);
        break;
    }
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    rrDomain = rr.rrDomain;
    rrType = rr.rrType;
    rrClass = rr.rrClass;
    ttl = rr.ttl;
    rdLen = rr.rdLen;
    rdata = malloc(rdLen);
    //memcpy(rdata, rr.rdata, rdLen);
    
    return *this;
}

string ResourceRecord::data() const
{
    string out = "";

    out += rrDomain;
    out += string((char*)&rrType, 2);
    out += string((char*)&rrClass, 2);
    out += string((char*)&ttl, 4);
    out += string((char*)&rdLen, 2);
    out += string((char*)rdata, rdLen);
    
    return out;
}
