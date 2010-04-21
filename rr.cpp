
#include "rr.hpp"

#include "dns_packet.hpp"

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

using namespace std;

extern ostream* theLog;

ResourceRecord::ResourceRecord()
{
    rrDomain = "";
    rrType = 0;
    rrClass = 0;
    ttl = 0;
    rdata = "";
}

ResourceRecord::ResourceRecord(const ResourceRecord& rr)
{
    *this = rr;
}

ResourceRecord::ResourceRecord(const string& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const string& rdata)
{
    uint32_t int32;
    //string str;
    unsigned type = atoi(rrType.data());
    
    *theLog << "Creating a resource record: " << rrDomain << "/" << rrType <<
        "/" << rrClass << "/" << ttl << "/" << rdata << endl;
    
    this->rrDomain = convertDomain(rrDomain);
    this->rrType = htons(type);
    this->rrClass = htons(atoi(rrClass.data()));
    this->ttl = htonl(atoi(ttl.data()));

    switch(type) {
        case 1: // A
            int32 = inet_addr(rdata.c_str());
            this->rdata = string((char*)&int32, 4);
        break;
        
        case 5: // CNAME
            this->rdata = convertDomain(rdata);
            cout << "RDATA " << this->rdata.size() << endl;
        break;
        
        default:
            throw runtime_error("Resource record type " + rrType + " not supported.");
    }
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    rrDomain = rr.rrDomain;
    rrType = rr.rrType;
    rrClass = rr.rrClass;
    ttl = rr.ttl;
    rdata = rr.rdata;
    
    return *this;
}

string ResourceRecord::data() const
{
    string out = "";

    uint16_t size;

    out += rrDomain;
    out += string((char*)&rrType, 2);
    out += string((char*)&rrClass, 2);
    out += string((char*)&ttl, 4);

    size = htons(rdata.size());
    out += string((char*)&size, 2);

    out += string(rdata.c_str(), rdata.size());
    return out;
}
