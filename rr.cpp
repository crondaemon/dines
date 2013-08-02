
#include <rr.hpp>

#include <dns_packet.hpp>
#include <fuzzer.hpp>
#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <stdlib.h>

using namespace std;

ResourceRecord::ResourceRecord()
{
    _rrDomain_str = "";
    _rrDomain_enc = "";
    _rrType = 0;
    _rrClass = 0;
    _ttl = 0;
    _rdata = "";
}

ResourceRecord::ResourceRecord(const ResourceRecord& rr)
{
    *this = rr;
}

ResourceRecord::ResourceRecord(const std::string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const char* rdata, unsigned rdatalen)
{
    string rd(rdata, rdatalen);
    *this = ResourceRecord(rrDomain, rrType, rrClass, ttl, rd);
}

ResourceRecord::ResourceRecord(const string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const string& rdata)
{
    // Domain
    _rrDomain_str = rrDomain;
    _rrDomain_enc = domainEncode(rrDomain);

    _rrType = htons(rrType);
    _rrClass = htons(rrClass);
    _ttl = htonl(ttl);
    _rdata = rdata;
}

ResourceRecord::ResourceRecord(const string& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const string& rdata)
{
    uint16_t type;
    uint16_t klass;
    unsigned int_ttl;

    // type
    if (rrType.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->rrType, 2);
        type = 1;
    } else {
        type = stringToQtype(rrType);
    }

    // class
    if (rrClass.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->rrClass, 2);
        klass = 1;
    } else {
        klass = stringToQclass(rrClass);
    }

    // ttl
    if (ttl.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->ttl, 4);
        int_ttl = 1;
    } else {
        int_ttl = atoi(ttl.data());
    }

    *this = ResourceRecord(rrDomain, type, klass, int_ttl, rdata);
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    _rrDomain_str = rr._rrDomain_str;
    _rrDomain_enc = rr._rrDomain_enc;

    _rrType = rr._rrType;
    //TODO
//    if (fuzzer.hasAddress(&rr.rrType)) {
//        fuzzer.delAddress(&rr.rrType);
//        fuzzer.addAddress(&rrType, 2);
//    }

    _rrClass = rr._rrClass;
//    if (fuzzer.hasAddress(&rr.rrClass)) {
//        fuzzer.delAddress(&rr.rrClass);
//        fuzzer.addAddress(&rrClass, 2);
//    }

    _ttl = rr._ttl;
//    if (fuzzer.hasAddress(&rr.ttl)) {
//        fuzzer.delAddress(&rr.ttl);
//        fuzzer.addAddress(&ttl, 4);
//    }

    _rdata = rr._rdata;

    return *this;
}

string ResourceRecord::data() const
{
    string out = "";

    uint16_t size;

    out += _rrDomain_enc;
    out += string((char*)&_rrType, 2);
    out += string((char*)&_rrClass, 2);
    out += string((char*)&_ttl, 4);

    size = htons(_rdata.size());
    out += string((char*)&size, 2);

    out += _rdata;
    return out;
}

string ResourceRecord::rrDomain() const
{
    return _rrDomain_str;
}

uint16_t ResourceRecord::rrType() const
{
    return ntohs(_rrType);
}

uint16_t ResourceRecord::rrClass() const
{
    return ntohs(_rrClass);
}

uint32_t ResourceRecord::ttl() const
{
    return ntohl(_ttl);
}

unsigned ResourceRecord::rdatalen() const
{
    return _rdata.size();
}

string ResourceRecord::rdata() const
{
    return _rdata;
}
