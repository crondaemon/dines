
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include <arpa/inet.h>
#include <string>

class DnsQuestion {
    //! plain version of the domain name
    std::string _qdomain_str;
    //! encoded version of the domain name
    std::string _qdomain_enc;

    uint16_t _qtype;
    uint16_t _qclass;

    bool _fuzzQtype;
    bool _fuzzQclass;
public:
    DnsQuestion() {}
    DnsQuestion(const std::string qdomain, unsigned qtype, unsigned qclass);
    DnsQuestion(const std::string qdomain, const std::string qtype, const std::string qclass);

    DnsQuestion& operator=(const DnsQuestion& q);


    std::string data() const;

    std::string qdomain() const;
    uint16_t qtype() const;
    uint16_t qclass() const;

    void fuzz();

    void fuzzQtype();
    void fuzzQclass();
};

#endif
