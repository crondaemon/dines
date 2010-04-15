
#include "DnsQuestion.hpp"

#include <iostream>
#include <arpa/inet.h>

using namespace std;

string DnsQuestion::data() const
{
    string out = "";
    uint16_t temp;
    
    out += _domain.data();
    
    temp = htons(_type);
    out += string((char*)&temp, 2);
    
    temp = htons(_class);
    out += string((char*)&temp, 2);
    
    return out;
}

