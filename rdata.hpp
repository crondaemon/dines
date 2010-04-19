
#ifndef __RDATA_HPP__
#define __RDATA_HPP__

#include <string>

class Rdata {
    void* _ptr;
    unsigned _type;
    unsigned _len;
public:
    Rdata() : _ptr(NULL), _type(0), _len(0) {}
    Rdata(const std::string data, const unsigned type);
    
    Rdata(const Rdata& r);
    
    unsigned len() const { return _len; }
    
    std::string data() const;
    
    Rdata& operator=(const Rdata& r);
    
    //~Rdata();
};

#endif
