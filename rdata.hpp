
#ifndef __RDATA_HPP__
#define __RDATA_HPP__

#include <string>

class Rdata {
public:
    Rdata() {}
    Rdata(const std::string dom, const unsigned type);
    
    std::string data() const;
};

#endif
