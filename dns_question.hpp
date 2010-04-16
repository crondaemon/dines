
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include "dns_domain.hpp"

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
public:
    DnsDomain qdomain;
    uint16_t qtype;
    uint16_t qclass;

    DnsQuestion() {}
    DnsQuestion(const DnsDomain d, const uint16_t type, const uint16_t cl) :
        qdomain(d),
        qtype(type),
        qclass(cl)
        {}
        
    std::string data() const;
};

#endif
