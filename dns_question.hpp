
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
    uint16_t stringToQtype(const std::string& s);
    uint16_t stringToQclass(const std::string& s);
    //! plain version of the domain name
    std::string _qdomain_str;
    //! encoded version of the domain name
    std::string _qdomain_enc;
public:
    uint16_t qtype;
    uint16_t qclass;

    DnsQuestion() {}
    DnsQuestion(DnsQuestion& q);
    DnsQuestion(const std::string& qdomain, unsigned qtype, unsigned qclass);
    DnsQuestion(const std::string& qdomain, const std::string& qtype, const std::string& qclass);

    DnsQuestion& operator=(const DnsQuestion& q);

    std::string data() const;

    std::string qdomain() const;
};

#endif
