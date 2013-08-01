
#include <rr.hpp>

#include <dns_packet.hpp>
#include <fuzzer.hpp>
#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

using namespace std;

extern ostream* theLog;

ResourceRecord::ResourceRecord()
{
    _rrDomain_str = "";
    _rrDomain_enc = "";
    rrType = 0;
    rrClass = 0;
    ttl = 0;
    rdata = "";
}

ResourceRecord::ResourceRecord(const ResourceRecord& rr)
{
    *this = rr;
}

ResourceRecord::ResourceRecord(const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen)
{
    string rd(rdata, rdatalen);
    ResourceRecord(rrDomain, rrType, rrClass, ttl, rd);
}

ResourceRecord::ResourceRecord(const string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const string& rdata)
{
    // Domain
    _rrDomain_str = rrDomain;
    _rrDomain_enc = convertDomain(rrDomain);

    this->rrType = rrType;
    this->rrClass = rrClass;
    this->ttl = ttl;

    this->rdata = rdata;
}

ResourceRecord::ResourceRecord(const string& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const string& rdata)
{
    uint32_t int32;
    unsigned type = atoi(rrType.data());
    unsigned klass;
    unsigned int_ttl;

    // type
    if (rrType.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->rrType, 2);
        this->rrType = 1;
        type = 1;
    } else {
        this->rrType = htons(type);
    }

    // class
    if (rrClass.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->rrClass, 2);
        klass = 1;
    } else {
        klass = htons(atoi(rrClass.data()));
    }

    // ttl
    if (ttl.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->ttl, 4);
        int_ttl = 1;
    } else {
        int_ttl = htonl(atoi(ttl.data()));
    }

    ResourceRecord(rrDomain, type, klass, int_ttl, rdata);
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    _rrDomain_str = rr._rrDomain_str;
    _rrDomain_enc = rr._rrDomain_enc;

    rrType = rr.rrType;
    //TODO
//    if (fuzzer.hasAddress(&rr.rrType)) {
//        fuzzer.delAddress(&rr.rrType);
//        fuzzer.addAddress(&rrType, 2);
//    }

    rrClass = rr.rrClass;
//    if (fuzzer.hasAddress(&rr.rrClass)) {
//        fuzzer.delAddress(&rr.rrClass);
//        fuzzer.addAddress(&rrClass, 2);
//    }

    ttl = rr.ttl;
//    if (fuzzer.hasAddress(&rr.ttl)) {
//        fuzzer.delAddress(&rr.ttl);
//        fuzzer.addAddress(&ttl, 4);
//    }

    rdata = rr.rdata;

    return *this;
}

string ResourceRecord::data() const
{
    string out = "";

    uint16_t size;

    out += _rrDomain_enc;
    out += string((char*)&rrType, 2);
    out += string((char*)&rrClass, 2);
    out += string((char*)&ttl, 4);

    size = htons(rdata.size());
    out += string((char*)&size, 2);

    out += string(rdata.c_str(), rdata.size());
    return out;
}

string ResourceRecord::rrDomain() const
{
    return _rrDomain_str;
}
