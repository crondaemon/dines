
#include "rr.hpp"

using namespace std;

ResourceRecord::ResourceRecord()
{
    rrType = 0;
    rrClass = 0;
    ttl = 0;
    rdLen = 0;
}

ResourceRecord::ResourceRecord(const DnsDomain& rrDomain, const uint16_t rrType,
        const uint16_t rrClass, const uint32_t ttl, const uint16_t rdLen,
        const Rdata& rrData)
{
    this->rrDomain = rrDomain;
    this->rrType = rrType;
    this->rrClass = rrClass;
    this->ttl = ttl;
    this->rdLen = rdLen;
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
