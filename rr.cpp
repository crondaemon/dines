
#include <rr.hpp>

#include <dns_packet.hpp>
#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

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
    _rData = rdata;

    _fuzzRRtype = false;
    _fuzzRRclass = false;
    _fuzzTTL = false;
    srand(time(NULL));
}

ResourceRecord::ResourceRecord(const string& rrDomain, const string& rrType,
        const string& rrClass, const string& ttl, const string& rdata)
{
    uint16_t type;
    uint16_t klass;
    unsigned int_ttl;

    type = stringToQtype(rrType);
    klass = stringToQclass(rrClass);
    int_ttl = atoi(ttl.data());

    *this = ResourceRecord(rrDomain, type, klass, int_ttl, rdata);
}

string ResourceRecord::data() const
{
    string out = "";

    uint16_t size;

    out += _rrDomain_enc;
    out += string((char*)&_rrType, 2);
    out += string((char*)&_rrClass, 2);
    out += string((char*)&_ttl, 4);

    size = htons(_rData.size());
    out += string((char*)&size, 2);

    out += _rData;
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

string ResourceRecord::rrTypeStr() const
{
    return qtypeToString(ntohs(_rrType));
}

uint16_t ResourceRecord::rrClass() const
{
    return ntohs(_rrClass);
}

string ResourceRecord::rrClassStr() const
{
    return qclassToString(ntohs(_rrClass));
}

uint32_t ResourceRecord::ttl() const
{
    return ntohl(_ttl);
}

string ResourceRecord::ttlStr() const
{
    char buf[11];
    snprintf(buf, 11, "%u", ntohl(_ttl));
    return string(buf);
}

string ResourceRecord::rData() const
{
    return _rData;
}

unsigned ResourceRecord::rDataLen() const
{
    return _rData.size();
}

void ResourceRecord::fuzz()
{
    if (_fuzzRRtype)
        _rrType = rand() % 65535;

    if (_fuzzRRclass)
        _rrClass = rand() % 65535;

    if (_fuzzTTL)
        _ttl = rand();
}

void ResourceRecord::fuzzRRtype()
{
    _fuzzRRtype = true;
}

void ResourceRecord::fuzzRRclass()
{
    _fuzzRRclass = true;
}

void ResourceRecord::fuzzRRttl()
{
    _fuzzTTL = true;
}

void ResourceRecord::rrType(string rrType)
{
    this->rrType(stringToQtype(rrType));
}

void ResourceRecord::rrType(unsigned rrType)
{
    _rrType = htons(rrType);
}

void ResourceRecord::rrClass(string rrClass)
{
    this->rrClass(stringToQclass(rrClass));
}

void ResourceRecord::rrClass(unsigned rrClass)
{
    _rrClass = htons(rrClass);
}

string ResourceRecord::to_string() const
{
    return _rrDomain_str + "/" + rrTypeStr() + "/" + rrClassStr() + "/" +
        ttlStr();
}

void ResourceRecord::rData(string rdata)
{
    _rData = rdata;
}
