
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
    ResourceRecord(const DnsDomain& rrDomain, const std::string rrType,
        const std::string rrClass, const std::string ttl, const Rdata& rrData);
        
    ResourceRecord(const ResourceRecord& rr);
    
    std::string data() const;
};

#endif
