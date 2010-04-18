
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
//    printf("%.4X zanzan\n", *(uint32_t*)_ptr);
    cout << "RDATA data " << _len << endl;
    return string((char*)_ptr, _len);;
}

Rdata::Rdata(const Rdata& rd)
{
    cout << "RDATA COPY " << endl;
    _ptr = malloc(rd._len);
    memcpy(_ptr, rd._ptr, rd._len);
    _type = rd._type;
    _len = rd._len;
    cout << "LEJ = " << rd._len << endl;
}

Rdata Rdata::operator=(const Rdata& r)
{
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
            cout << "METTO IP " << data << endl;
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
