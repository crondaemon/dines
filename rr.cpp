
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

ResourceRecord::ResourceRecord(const string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const string& rdata)
{
    // Domain
    _rrDomain_str = rrDomain;
    _rrDomain_enc = Dines::domainEncode(rrDomain);

    _rrType = htons(rrType);
    _rrClass = htons(rrClass);
    _ttl = htonl(ttl);
    _rData = rdata;

    _fuzzRRdomain = false;
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

    type = Dines::stringToQtype(rrType);
    klass = Dines::stringToQclass(rrClass);
    int_ttl = stoul(ttl.data());

    *this = ResourceRecord(rrDomain, type, klass, int_ttl, rdata);
}

ResourceRecord::ResourceRecord(const ResourceRecord& rr)
{
    *this = rr;
}

ResourceRecord& ResourceRecord::operator=(const ResourceRecord& rr)
{
    _rrDomain_str = rr._rrDomain_str;
    _rrDomain_enc = rr._rrDomain_enc;

    _rrType = rr._rrType;
    _rrClass = rr._rrClass;
    _ttl = rr._ttl;
    _rData = rr._rData;

    _fuzzRRdomain = rr._fuzzRRdomain;
    _fuzzRRtype = rr._fuzzRRtype;
    _fuzzRRclass = rr._fuzzRRclass;
    _fuzzTTL = rr._fuzzTTL;

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
    return Dines::qtypeToString(ntohs(_rrType));
}

uint16_t ResourceRecord::rrClass() const
{
    return ntohs(_rrClass);
}

string ResourceRecord::rrClassStr() const
{
    return Dines::qclassToString(ntohs(_rrClass));
}

uint32_t ResourceRecord::ttl() const
{
    return ntohl(_ttl);
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
    if (_fuzzRRdomain == true) {
        for (unsigned i = 0; i < _rrDomain_enc.size(); ++i) {
            _rrDomain_enc[i] = rand();
        }
    }

    if (_fuzzRRtype)
        _rrType = rand();

    if (_fuzzRRclass)
        _rrClass = rand();

    if (_fuzzTTL)
        _ttl = rand();
}

void ResourceRecord::fuzzRRdomain(unsigned len)
{
    _rrDomain_str = "[fuzzed]";
    _rrDomain_enc = string(len, 'x');
    _fuzzRRdomain = true;
    this->fuzz();
}

void ResourceRecord::fuzzRRtype()
{
    _fuzzRRtype = true;
    this->fuzz();
}

void ResourceRecord::fuzzRRclass()
{
    _fuzzRRclass = true;
    this->fuzz();
}

void ResourceRecord::fuzzRRttl()
{
    _fuzzTTL = true;
    this->fuzz();
}

void ResourceRecord::rrType(string rrType)
{
    this->rrType(Dines::stringToQtype(rrType));
}

void ResourceRecord::rrType(unsigned rrType)
{
    _rrType = htons(rrType);
}

void ResourceRecord::rrClass(string rrClass)
{
    this->rrClass(Dines::stringToQclass(rrClass));
}

void ResourceRecord::rrClass(unsigned rrClass)
{
    _rrClass = htons(rrClass);
}

string ResourceRecord::to_string() const
{
    string out = _rrDomain_str + "/" + this->rrTypeStr() + "/" + this->rrClassStr() + "/" +
        Dines::convertInt<int32_t>(this->ttl());

    if (Dines::qtypeToString(ntohs(_rrType)) == "A") {
        char addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, _rData.data(), addr, INET_ADDRSTRLEN);
        out += "/" + string(addr);
    }

    if (Dines::qtypeToString(ntohs(_rrType)) == "NS") {
        out += "/" + _rrDomain_str;
    }

    return out;
}

void ResourceRecord::rData(string rdata)
{
    _rData = rdata;
}
