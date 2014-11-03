
#ifndef __DNSQUESTION_HPP__
#define __DNSQUESTION_HPP__

#include <arpa/inet.h>
#include <string>
#include <utils.hpp>

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

    Dines::LogFunc _log;
public:
    DnsQuestion(const std::string qdomain = "", const std::string qtype = "A", const std::string qclass = "IN");
    DnsQuestion(const std::string qdomain, uint16_t qtype, uint16_t qclass);
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

    DnsQuestion& fuzz();

    void fuzzQdomain(unsigned len);
    bool fuzzQdomain() const;
    void fuzzQtype(bool fuzz);
    bool fuzzQtype() const;
    void fuzzQclass(bool fuzz);
    bool fuzzQclass() const;

    std::string to_string() const;

    size_t parse(char* buf, unsigned buflen, unsigned offset = 0);

    bool empty() const;

    //! Set the logger
    void logger(Dines::LogFunc l);

    void clear();
};

std::ostream& operator<<(std::ostream& o, const DnsQuestion& q);

#endif
