
#include <dns_question.hpp>

#include <dns_packet.hpp>
#include <fuzzer.hpp>
#include <convert.hpp>

#include <iostream>
#include <arpa/inet.h>
#include <stdexcept>

using namespace std;

extern ostream* theLog;

uint16_t DnsQuestion::stringToQtype(const std::string& s)
{
    if (s == "A") return 1;
    if (s == "NS") return 2;
    if (s == "CNAME") return 5;
    if (s == "PTR") return 12;
    if (s == "HINFO")  return 13;
    if (s == "MX")  return 15;
    if (s == "TXT") return 16;
    if (s == "AXFR") return 252;
    if (s == "ANY") return 255;

    unsigned n = atoi(s.c_str());

    if (n > 0xFFFF || n == 0) {
        return 0;
    }

    return n;
}

uint16_t DnsQuestion::stringToQclass(const std::string& s)
{
    return 1;
}

DnsQuestion::DnsQuestion(DnsQuestion& q)
{
    *this = q;
}

DnsQuestion& DnsQuestion::operator=(const DnsQuestion& q)
{
    _qdomain_str = q._qdomain_str;
    _qdomain_enc = q._qdomain_enc;
    qtype = q.qtype;
    qclass = q.qclass;

    // TODO
//    if (fuzzer.hasAddress((void*)&q.qtype)) {
//        fuzzer.delAddress((void*)&q.qtype);
//        fuzzer.addAddress((void*)&qtype, 2);
//    }

//    if (fuzzer.hasAddress((void*)&q.qclass)) {
//        fuzzer.delAddress((void*)&q.qclass);
//        fuzzer.addAddress((void*)&qclass, 2);
//    }

    return *this;
}

DnsQuestion::DnsQuestion(const string& qdomain, const string& qtype, const string& qclass)
{
    unsigned myqtype;
    unsigned myqclass;

    if (qtype.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->qtype, 2);
        myqtype = 1;
    } else {
        myqtype = stringToQtype(qtype);
    }

    if (qclass.at(0) == 'F') {
        throw runtime_error("NOT IMPLEMENTED");
        //fuzzer.addAddress(&this->qclass, 2);
        myqclass = 1;
    } else {
        myqclass = stringToQclass(qclass);
    }

    DnsQuestion(qdomain, myqtype, myqclass);
}

DnsQuestion::DnsQuestion(const string& qdomain, unsigned qtype, unsigned qclass)
{
    // Domain
    _qdomain_str = qdomain;
    _qdomain_enc = convertDomain(qdomain);

    // qtype
    this->qtype = qtype;

    // qclass
    this->qclass = qclass;
}

string DnsQuestion::data() const
{
    string out = "";
    uint16_t temp;

    out += _qdomain_enc;

    temp = htons(qtype);
    out += string((char*)&temp, 2);

    temp = htons(qclass);
    out += string((char*)&temp, 2);

    return out;
}

string DnsQuestion::qdomain() const
{
    return _qdomain_str;
}
