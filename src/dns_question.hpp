
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

    bool _fuzzQdomain;
    bool _fuzzQtype;
    bool _fuzzQclass;
public:
    DnsQuestion(const std::string qdomain = "", uint16_t qtype = 0, uint16_t qclass = 0);
    DnsQuestion(const std::string qdomain, const std::string qtype, const std::string qclass);
    DnsQuestion(const DnsQuestion& q);

    DnsQuestion& operator=(const DnsQuestion& q);

    bool operator==(const DnsQuestion& q) const;
    bool operator!=(const DnsQuestion& q) const;

    std::string data() const;

    std::string qdomain() const;

    void qtype(uint16_t qtype);
    uint16_t qtype() const;
    std::string qtypeStr() const;

    void qclass(uint16_t qclass);
    uint16_t qclass() const;
    std::string qclassStr() const;

    void fuzz();

    void fuzzQdomain(unsigned len);
    void fuzzQtype();
    void fuzzQclass();

    std::string to_string() const;

    void parse(char* buf);

    bool empty() const;
};

#endif
