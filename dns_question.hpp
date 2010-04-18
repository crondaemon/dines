
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include "dns_domain.hpp"

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
    uint16_t stringToQtype(std::string s);
    uint16_t stringToQclass(std::string s);
public:
    DnsDomain qdomain;
    uint16_t qtype;
    uint16_t qclass;

    DnsQuestion() {}
    DnsQuestion(const DnsDomain& qdomain, const std::string qtype, const std::string qclass);
        
    std::string data() const;
};

#endif
