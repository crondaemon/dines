
#ifndef __RR_HPP__
#define __RR_HPP__

#include <string>
#include <stdint.h>

class ResourceRecord {
    std::string _rrDomain_str;
    std::string _rrDomain_enc;
public:
    uint16_t rrType;
    uint16_t rrClass;
    uint32_t ttl;
    std::string rdata;

    ResourceRecord();
    ResourceRecord(const std::string& rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata);
    ResourceRecord(const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const std::string& rdata);
    ResourceRecord(const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen);

    ResourceRecord(const ResourceRecord& rr);

    std::string rrDomain() const;

    std::string data() const;

    ResourceRecord& operator=(const ResourceRecord& rr);
};

#endif
