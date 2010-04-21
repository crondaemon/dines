
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
    uint16_t stringToQtype(const std::string& s);
    uint16_t stringToQclass(const std::string& s);
public:
    std::string qdomain;
    uint16_t qtype;
    uint16_t qclass;

    DnsQuestion() {}
    DnsQuestion(const std::string& qdomain, const std::string& qtype, const std::string& qclass);
        
    std::string data() const;
};

#endif
