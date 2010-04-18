
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
    cout << "rr copy constr" << endl;
    rrDomain = rr.rrDomain;
    cout << "MARK" << endl;
    rrType = htons(rr.rrType);
    rrClass = htons(rr.rrClass);
    ttl = htonl(rr.ttl);
    rdLen = htons(rr.rdLen);
    rrData = rr.rrData;
    cout << "rr copy end" << endl;
}

ResourceRecord::ResourceRecord(const DnsDomain& rrDomain, const string rrType,
        const string rrClass, const string ttl, const Rdata& rrData)
{
    this->rrDomain = rrDomain;
    this->rrType = atoi(rrType.data());
    this->rrClass = atoi(rrClass.data());
    this->ttl = atoi(ttl.data());
    this->rdLen = rrData.len();
    this->rrData = rrData;
}

ResourceRecord ResourceRecord::operator=(const ResourceRecord& rr)
{
    cout << "RR operator = " << endl;
    return ResourceRecord(rr);
    cout << "RR operator = done" << endl;
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
    cout << " MO JE METTO " << rrDomain.data().length() << endl;
    
    return out;
}
