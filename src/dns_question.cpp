
#include <dns_question.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

DnsQuestion::DnsQuestion(const string qdomain, const string qtype, const string qclass)
{
    *this = DnsQuestion(qdomain, Dines::stringToQtype(qtype), Dines::stringToQclass(qclass));

    if (qtype == "F") {
        this->fuzzQtype(true);
    }

    if (qclass == "F") {
        this->fuzzQclass(true);
    }
    _fuzzQtype = false;
    _fuzzQclass = false;
}

DnsQuestion::DnsQuestion(const string qdomain, uint16_t qtype, uint16_t qclass)
{
    _fuzzQtype = false;
    _fuzzQclass = false;

    // Domain
    if (qdomain.size() > 0 && qdomain.at(0) == 'F') {
        unsigned len;
        try {
            len = stoul(qdomain.substr(1).data());
        } catch (exception& e) {
            len = 0;
        }
        if (len == 0) {
            throw runtime_error(string("Invalid format for fuzzer:\n"
                "F must be followed by fuzzed length\n"
                "Syntax: --question F<n>,<type>,<class>\n\n"));
        }
        fuzzQdomain(len);
    } else {
        _qdomain_str = qdomain;
        _qdomain_enc = Dines::domainEncode(qdomain);
        _fuzzQdomain = false;
    }
    // qtype
    _qtype = htons(qtype);

    // qclass
    _qclass = htons(qclass);
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

DnsQuestion& DnsQuestion::fuzz()
{
    if (_fuzzQdomain == true) {
        _qdomain_str = Dines::random_string(_qdomain_str.size());
        _qdomain_enc = Dines::domainEncode(_qdomain_str);
    }

    if (_fuzzQtype == true) {
        _qtype = Dines::random_16();
    }

    if (_fuzzQclass == true) {
        _qclass = Dines::random_16();
    }

    return *this;
}

void DnsQuestion::fuzzQdomain(unsigned len)
{
    _qdomain_str = string(len, 'x');
    _qdomain_enc = Dines::domainEncode(_qdomain_str);
    _fuzzQdomain = true;
    this->fuzz();
}

void DnsQuestion::fuzzQtype(bool fuzz)
{
    _fuzzQtype = fuzz;
    this->fuzz();
}

bool DnsQuestion::fuzzQtype() const
{
    return _fuzzQtype;
}

bool DnsQuestion::fuzzQclass() const
{
    return _fuzzQclass;
}

void DnsQuestion::fuzzQclass(bool fuzz)
{
    _fuzzQclass = fuzz;
    this->fuzz();
}

string DnsQuestion::to_string() const
{
    return _qdomain_str + "/" + qtypeStr() + "/" + qclassStr();
}

size_t DnsQuestion::parse(char* buf, unsigned buflen, unsigned offset)
{
    unsigned i;

    this->clear();

    i = Dines::domainDecode(buf, buflen, offset, _qdomain_enc, _qdomain_str);

    if (buflen - i < 4) {
        if (_log)
            _log(string(__func__) + ": Not enough data");
        return i;
    }

    memcpy(&_qtype, buf + offset + i, 2);
    memcpy(&_qclass, buf + offset + i + 2, 2);
    return (_qdomain_enc.size() + 4);
}

bool DnsQuestion::empty() const
{
    if (_qdomain_str == "" && ntohs(_qtype) == 1 && ntohs(_qclass) == 1)
        return true;

    return false;
}

void DnsQuestion::logger(Dines::LogFunc l)
{
    _log = l;
}

void DnsQuestion::clear()
{
    _qdomain_enc.clear();
    _qdomain_str.clear();
    _qtype = 1;
    _qclass = 1;
}

std::ostream& operator<<(std::ostream& o, const DnsQuestion& q)
{
    return o << q.to_string();
}
