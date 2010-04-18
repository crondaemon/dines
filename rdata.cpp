
#include "rdata.hpp"

#include <stdexcept>
#include <sstream>
#include <iostream>

#include <cstring>

#include "dns_domain.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
       
using namespace std;

string Rdata::data() const
{
    return string((char*)_ptr, _len);;
}

Rdata::Rdata(const Rdata& rd)
{
    _ptr = malloc(rd._len);
    memcpy(_ptr, rd._ptr, rd._len);
    _type = rd._type;
    _len = rd._len;
}

Rdata Rdata::operator=(const Rdata& r)
{
    cout << "RDATA operator =" << endl;
    return Rdata(r);
}

Rdata::Rdata(const std::string data, const unsigned type)
{
    _type = 0;
    _len = 0;
    _ptr = NULL;
    
    switch(type) {
        case 1:
        {
            uint32_t ip = inet_addr(data.c_str());
            _ptr = malloc(4);
            memcpy(_ptr, &ip, 4);
            _len = 4;
        }
        break;
        
        default:
            stringstream ss;
            ss << "Type ";
            ss << type;
            ss << " not supported.";
            throw runtime_error(ss.str());
    }
    _type = type;
}
