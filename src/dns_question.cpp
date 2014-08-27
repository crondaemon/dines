
#include <dns_question.hpp>

#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

DnsQuestion::DnsQuestion(const string qdomain, const string qtype, const string qclass)
{
    unsigned myqtype;
    unsigned myqclass;

    myqtype = Dines::stringToQtype(qtype);
    myqclass = Dines::stringToQclass(qclass);

    *this = DnsQuestion(qdomain, myqtype, myqclass);
}

DnsQuestion::DnsQuestion(const string qdomain, uint16_t qtype, uint16_t qclass)
{
    // Domain
    _qdomain_str = qdomain;
    _qdomain_enc = Dines::domainEncode(qdomain);

    // qtype
    _qtype = htons(qtype);

    // qclass
    _qclass = htons(qclass);

    _fuzzQdomain = false;
    _fuzzQtype = false;
    _fuzzQclass = false;
    srand(time(NULL));
}

DnsQuestion::DnsQuestion(const DnsQuestion& q)
{
    *this = q;
}

DnsQuestion& DnsQuestion::operator=(const DnsQuestion& q)
{
    _qdomain_str = q._qdomain_str;
    _qdomain_enc = q._qdomain_enc;
    _qtype = q._qtype;
    _qclass = q._qclass;
    _fuzzQdomain = q._fuzzQdomain;
    _fuzzQtype = q._fuzzQtype;
    _fuzzQclass = q._fuzzQclass;

    return *this;
}

bool DnsQuestion::operator==(const DnsQuestion& q) const
{
    return (
        _qdomain_str == q._qdomain_str &&
        _qdomain_enc == q._qdomain_enc &&
        _qtype == q._qtype &&
        _qclass == q._qclass);
}

bool DnsQuestion::operator!=(const DnsQuestion& q) const
{
    return !(*this == q);
}

string DnsQuestion::data() const
{
    return _qdomain_enc + string((char*)&_qtype, 2) + string((char*)&_qclass, 2);
}

string DnsQuestion::qdomain() const
{
    return _qdomain_str;
}

void DnsQuestion::qtype(uint16_t qtype)
{
    _qtype = htons(qtype);
}

void DnsQuestion::qclass(uint16_t qclass)
{
    _qclass = htons(qclass);
}

uint16_t DnsQuestion::qclass() const
{
    return ntohs(_qclass);
}

string DnsQuestion::qclassStr() const
{
    return Dines::qclassToString(ntohs(_qclass));
}

uint16_t DnsQuestion::qtype() const
{
    return ntohs(_qtype);
}

string DnsQuestion::qtypeStr() const
{
    return Dines::qtypeToString(ntohs(_qtype));
}

void DnsQuestion::fuzz()
{
    if (_fuzzQdomain == true) {
        for (unsigned i = 0; i < _qdomain_enc.size(); ++i) {
            _qdomain_enc[i] = rand();
        }
    }

    if (_fuzzQtype == true) {
        _qtype = rand();
    }

    if (_fuzzQclass == true) {
        _qclass = rand();
    }
}

void DnsQuestion::fuzzQdomain(unsigned len)
{
    _qdomain_str = "[fuzzed]";
    _qdomain_enc.resize(len);
    _fuzzQdomain = true;
    this->fuzz();
}

void DnsQuestion::fuzzQtype()
{
    _fuzzQtype = true;
    this->fuzz();
}

void DnsQuestion::fuzzQclass()
{
    _fuzzQclass = true;
    this->fuzz();
}

string DnsQuestion::to_string() const
{

    return _qdomain_str + "/" + qtypeStr() + "/" + qclassStr();
}

void DnsQuestion::parse(char* buf)
{
    unsigned i = 0;
    while (buf[i] != 0)
        i++;
    i++;
    _qdomain_enc = string(buf, i);

    // Now parse the domain into printable form
    _qdomain_str = "";
    int cur = 1;
    int len = buf[0];
    while (len != 0) {
        _qdomain_str += string(buf + cur, len);
        _qdomain_str += ".";
        cur += len;
        len = buf[cur];
        cur++;
    }
    _qdomain_str.erase(_qdomain_str.size() - 1, _qdomain_str.size());

    memcpy(&_qtype, buf + i, 2);
    memcpy(&_qclass, buf + i + 2, 2);
}

bool DnsQuestion::empty() const
{
    if (_qdomain_str == "" && _qtype == 0 && _qclass == 0)
        return true;

    return false;
}
