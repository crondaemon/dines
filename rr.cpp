
#include "rr.hpp"

using namespace std;

ResourceRecord::ResourceRecord()
{
    rrType = 0;
    rrClass = 0;
    ttl = 0;
    rdLen = 0;
}

ResourceRecord::ResourceRecord(const DnsDomain& rrDomain, const string rrType,
        const string rrClass, const string ttl, const string rdLen,
        const Rdata& rrData)
{
    this->rrDomain = rrDomain;
    this->rrType = atoi(rrType.data());
    this->rrClass = atoi(rrClass.data());
    this->ttl = atoi(ttl.data());
    this->rdLen = atoi(rdLen.data());
    this->rrData = rrData;
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
