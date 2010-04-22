
#ifndef __RR_HPP__
#define __RR_HPP__

#include <string>

class ResourceRecord {
public:
    std::string rrDomain;
    uint16_t rrType;
    uint16_t rrClass;
    uint32_t ttl;
    std::string rdata;
        
    ResourceRecord();
    ResourceRecord(const std::string& rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata);
        
    ResourceRecord(const ResourceRecord& rr);
      
    std::string data() const;
    
    ResourceRecord& operator=(const ResourceRecord& rr);
};

#endif
