
#include "dns_question.hpp"

#include <iostream>
#include <arpa/inet.h>

using namespace std;

extern ostream* theLog;

uint16_t DnsQuestion::stringToQtype(std::string s)
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
        *theLog << "Invalid qtype: " << s << endl;
        return 0;
    }
    
    return n;
}

uint16_t DnsQuestion::stringToQclass(std::string s)
{
    return 1;
}

DnsQuestion::DnsQuestion(const DnsDomain& qdomain, const string qtype, const string qclass) :
    qdomain(qdomain)
{
    this->qtype = stringToQtype(qtype);
    this->qclass = stringToQclass(qclass);
    *theLog << "Creating question: " << qdomain.str() << "/" << this->qtype << 
        "/" << this->qclass << endl;
}

string DnsQuestion::data() const
{
    string out = "";
    uint16_t temp;
    
    out += qdomain.data();
    
    temp = htons(qtype);
    out += string((char*)&temp, 2);
    
    temp = htons(qclass);
    out += string((char*)&temp, 2);
    
    return out;
}

