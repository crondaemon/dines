
#include <dns_question.hpp>

#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

DnsQuestion::DnsQuestion(const string qdomain, const string qtype, const string qclass)
{
    unsigned myqtype;
    unsigned myqclass;

    myqtype = stringToQtype(qtype);
    myqclass = stringToQclass(qclass);

    *this = DnsQuestion(qdomain, myqtype, myqclass);
}

DnsQuestion::DnsQuestion(const string qdomain, unsigned qtype, unsigned qclass)
{
    // Domain
    _qdomain_str = qdomain;
    _qdomain_enc = domainEncode(qdomain);

    // qtype
    _qtype = qtype;

    // qclass
    _qclass = qclass;

    _fuzzQtype = false;
    _fuzzQclass = false;
    srand(time(NULL));
}

string DnsQuestion::data() const
{
    string out = "";
    uint16_t temp;

    out += _qdomain_enc;

    temp = htons(_qtype);
    out += string((char*)&temp, 2);

    temp = htons(_qclass);
    out += string((char*)&temp, 2);

    return out;
}

string DnsQuestion::qdomain() const
{
    return _qdomain_str;
}

uint16_t DnsQuestion::qclass() const
{
    return _qclass;
}

uint16_t DnsQuestion::qtype() const
{
    return _qtype;
}

void DnsQuestion::fuzz()
{
    if (_fuzzQtype == true) {
        _qtype = rand() % 65535;
    }

    if (_fuzzQclass == true) {
        _qclass = rand() % 65535;
    }
}

void DnsQuestion::fuzzQtype()
{
    _fuzzQtype = true;
}

void DnsQuestion::fuzzQclass()
{
    _fuzzQclass = true;
}
