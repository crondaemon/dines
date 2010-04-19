
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

Rdata::Rdata(const Rdata& r)
{
    *this = r;    
}

Rdata& Rdata::operator=(const Rdata& r)
{
    _type = r._type;
    _len = r._len;
    _ptr = malloc(r._len);
    if (_ptr == NULL)
        throw runtime_error("Rdata malloc failed");
        
    cout << "ALLOCO " << r._len << endl;
    cout << "Sto per copiare da " << r._ptr << " a " << _ptr << endl;
    memcpy(_ptr, r._ptr, r._len);
    
    return *this;
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

//Rdata::~Rdata()
//{
//    free(_ptr);
//}

