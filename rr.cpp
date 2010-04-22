
#include "rr.hpp"

#include "dns_packet.hpp"
#include "fuzzer.hpp"

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

using namespace std;

extern ostream* theLog;
extern Fuzzer fuzzer;

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
    unsigned type = atoi(rrType.data());
    
    //*theLog << "Creating a resource record: " << rrDomain << "/" << rrType <<
    //    "/" << rrClass << "/" << ttl << "/" << rdata << endl;
    
    // Domain
    this->rrDomain = convertDomain(rrDomain);
    
    // type
    if (rrType.at(0) == 'F') {
        fuzzer.addAddress(&this->rrType, 2);
        this->rrType = 1;
        type = 1;
    } else {
        this->rrType = htons(type);
    }
    
    // class
    if (rrClass.at(0) == 'F') {
        fuzzer.addAddress(&this->rrClass, 2);
        this->rrClass = 1;
    } else {
        this->rrClass = htons(atoi(rrClass.data()));
    }
    
    // ttl
    if (ttl.at(0) == 'F') {
        fuzzer.addAddress(&this->ttl, 4);
        this->ttl = 1;
    } else {
        this->ttl = htonl(atoi(ttl.data()));
    }

    switch(type) {
        case 1: // A
            int32 = inet_addr(rdata.c_str());
            this->rdata = string((char*)&int32, 4);
        break;
        
        case 2: // NS
        case 5: // CNAME
            this->rdata = convertDomain(rdata);
        break;
        
        case 15: // MX
            this->rdata = string("\x00\x00", 2);
            this->rdata += convertDomain(rdata);
        break;
        
        default:
            throw runtime_error("Resource record type " + rrType + " not supported.");
    }
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    rrDomain = rr.rrDomain;
    
    rrType = rr.rrType;
    if (fuzzer.hasAddress(&rr.rrType)) {
        fuzzer.delAddress(&rr.rrType);
        fuzzer.addAddress(&rrType, 2);
    }
    
    rrClass = rr.rrClass;
    if (fuzzer.hasAddress(&rr.rrClass)) {
        fuzzer.delAddress(&rr.rrClass);
        fuzzer.addAddress(&rrClass, 2);
    }
    
    ttl = rr.ttl;
    if (fuzzer.hasAddress(&rr.ttl)) {
        fuzzer.delAddress(&rr.ttl);
        fuzzer.addAddress(&ttl, 4);
    }
    
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
