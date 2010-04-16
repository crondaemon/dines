
#include "dns_question.hpp"

#include <iostream>
#include <arpa/inet.h>

using namespace std;

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

