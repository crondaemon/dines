
#ifndef __RR_HPP__
#define __RR_HPP__

#include <string>
#include <stdint.h>

class ResourceRecord {
    std::string _rrDomain_str;
    std::string _rrDomain_enc;

    uint16_t _rrType;
    uint16_t _rrClass;
    uint32_t _ttl;
    std::string _rData;
public:

    ResourceRecord();
    ResourceRecord(const std::string& rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata);
    ResourceRecord(const std::string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const std::string& rdata);
    ResourceRecord(const std::string& rrDomain, uint16_t rrType,
        uint16_t rrClass, uint32_t ttl, const char* rdata, unsigned rdatalen);

    ResourceRecord(const ResourceRecord& rr);

    std::string rrDomain() const;

    std::string data() const;

    ResourceRecord& operator=(const ResourceRecord& rr);

    uint16_t rrType() const;
    uint16_t rrClass() const;
    uint32_t ttl() const;
    std::string rData() const;
    unsigned rDataLen() const;
};

#endif
