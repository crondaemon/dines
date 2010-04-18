
#ifndef __RR_HPP__
#define __RR_HPP__

#include <string>

#include "dns_domain.hpp"
#include "rdata.hpp"

class ResourceRecord {
public:
    DnsDomain rrDomain;
    uint16_t rrType;
    uint16_t rrClass;
    uint32_t ttl;
    uint16_t rdLen;
    Rdata rrData;
    
    ResourceRecord();
    ResourceRecord(const DnsDomain& rrDomain, const uint16_t rrType,
        const uint16_t rrClass, const uint32_t ttl, const uint16_t rdLen,
        const Rdata& rrData);
        
    std::string data() const;
};

#endif
