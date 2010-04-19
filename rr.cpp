
#include "rr.hpp"

#include <iostream>

#include <arpa/inet.h>

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

ResourceRecord::ResourceRecord(const DnsDomain& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const Rdata& rrData)
{
    this->rrDomain = rrDomain;
    this->rrType = htons(atoi(rrType.data()));
    this->rrClass = htons(atoi(rrClass.data()));
    this->ttl = htonl(atoi(ttl.data()));
    this->rdLen = htons(rrData.len());
    this->rrData = rrData;
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    rrDomain = rr.rrDomain;
    rrType = rr.rrType;
    rrClass = rr.rrClass;
    ttl = rr.ttl;
    rdLen = rr.rdLen;
    rrData = rr.rrData;
    
    return *this;
}

string ResourceRecord::data() const
{
    string out = "";

    out += rrDomain.data();
    out += string((char*)&rrType, 2);
    out += string((char*)&rrClass, 2);
    out += string((char*)&ttl, 4);
    out += string((char*)&rdLen, 2);
    out += rrData.data();
    
    return out;
}
