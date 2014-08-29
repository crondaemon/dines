
#include <rr.hpp>

#include <dns_packet.hpp>
#include <utils.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <stdlib.h>
#include <stdio.h>

#include <algorithm>

using namespace std;

ResourceRecord::ResourceRecord(const string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const string& rdata)
{
    // Domain
    if (rrDomain.size() > 0 && rrDomain.at(0) == 'F') {
        unsigned len;
        try {
            len = stoul(rrDomain.substr(1).data());
        } catch (exception& e) {
            len = 0;
        }
        if (len == 0) {
            throw runtime_error(string("Invalid format for fuzzer:\n"
                "F must be followed by fuzzed length\n"
                "Syntax: --{answer|auth|add} F<n>,<type>,<class>,ttl,rdata\n\n"
                "Syntax: --{answer|auth|add} F<n>,<type>,<class>,ttl,rdatalen,rdata\n\n"));
        }
        fuzzRRdomain(len);
    } else {
        _rrDomain_str = rrDomain;
        _rrDomain_enc = Dines::domainEncode(rrDomain);
        _fuzzRRdomain = false;
    }

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

    if (rrType == "F") {
        _fuzzRRtype = true;
        type = 0;
    } else {
        type = Dines::stringToQtype(rrType);
    }

    if (rrClass == "F") {
        _fuzzRRclass = true;
        klass = 0;
    } else {
        klass = Dines::stringToQclass(rrClass);
    }

    if (ttl == "F") {
        _fuzzTTL = true;
        int_ttl = 0;
    } else {
        int_ttl = stoul(ttl.data());
    }

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

ResourceRecord& ResourceRecord::fuzz()
{
    if (_fuzzRRdomain == true) {
        _rrDomain_str = Dines::random_string(_rrDomain_str.size());
        _rrDomain_enc = Dines::domainEncode(_rrDomain_str);
    }

    if (_fuzzRRtype)
        _rrType = rand();

    if (_fuzzRRclass)
        _rrClass = rand();

    if (_fuzzTTL)
        _ttl = rand();

    return *this;
}

void ResourceRecord::fuzzRRdomain(unsigned len)
{
    _rrDomain_str = string(len, 'x');
    _rrDomain_enc = Dines::domainEncode(_rrDomain_str);
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

void ResourceRecord::rrDomain(string domain)
{
    _rrDomain_str = domain;
    _rrDomain_enc = Dines::domainEncode(domain);
}

string ResourceRecord::to_string() const
{
    string out = _rrDomain_str + "/" + this->rrTypeStr() + "/" + this->rrClassStr() + "/" +
        std::to_string(this->ttl());

    if (Dines::qtypeToString(ntohs(_rrType)) == "A") {
        char addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, _rData.data(), addr, INET_ADDRSTRLEN);
        out += "/" + string(addr);
    }

    if (Dines::qtypeToString(ntohs(_rrType)) == "NS") {
        out += "/" + this->rData();
    }

    return out;
}

void ResourceRecord::rData(string rdata)
{
    _rData = rdata;
}

void ResourceRecord::logger(Dines::LogFunc l)
{
    _log = l;
}
