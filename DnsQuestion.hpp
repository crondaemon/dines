
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include "DnsDomain.hpp"

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
    DnsDomain _domain;
    uint16_t _type;
    uint16_t _class;
public:
    DnsQuestion() {}
    DnsQuestion(const DnsDomain d, const uint16_t type, const uint16_t cl) :
        _domain(d),
        _type(type),
        _class(cl)
        {}
        
    std::string data() const;
};

#endif
