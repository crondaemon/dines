
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <stdint.h>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <dns_header.hpp>
#include <dns_question.hpp>
#include <rr.hpp>
#include <tokenizer.hpp>
#include <fuzzer.hpp>

class DnsPacket {
    int _socket;
    struct sockaddr_in _sin;
    struct sockaddr_in _din;

    //! Creates the socket
    void socketCreate();

    //! The fuzzer
    Fuzzer fuzzer;

    //! IP layer
    struct iphdr _ipHdr;

    //! UDP layer
    struct udphdr _udpHdr;

    //! DNS header
    DnsHeader _dnsHdr;

    //! DNS question
    DnsQuestion _question;

    //! DNS answers
    std::vector<ResourceRecord> _answers;

    //! DNS authoritative
    std::vector<ResourceRecord> _authorities;

    //! DNS additionals
    std::vector<ResourceRecord> _additionals;

public:

    typedef enum {
        R_QUESTION = 0,
        R_ANSWER = 1,
        R_ADDITIONAL = 2,
        R_AUTHORITIES = 3
    } RecordSection;

    //! Constructor
    DnsPacket();

    //! DNS SECTION

    //! Compute the UDP checksum
    void doUdpCksum();

    //! Raw data getter
    std::string data() const;

    //! Sends the packet into the network
    void sendNet();

    //! to_string
    std::string to_string() const;

    void ipFrom(std::string ip_from);

    void ipTo(std::string ip_to);

    //! IP source as string
    std::string ipFrom() const;

    //! IP dest as string
    std::string ipTo() const;

    uint16_t sport() const;

    void sport(std::string sport);

    uint16_t dport() const;

    void dport(std::string dport);

    uint16_t txid() const;

    void txid(std::string txid);

    //! Nrecord
    uint16_t nrecord(DnsPacket::RecordSection section) const;

    void nrecord(DnsPacket::RecordSection section, uint32_t value);

    //! TODO
    bool isRecursive() const;

    void isQuestion(bool isQuestion);

    //! TODO
    bool isQuestion() const;

    //! TODO
    const DnsQuestion& question() const;

    const ResourceRecord& answers(unsigned n) const;
    const ResourceRecord& additionals(unsigned n) const;
    const ResourceRecord& authorities(unsigned n) const;

    //! Adds a question
    void addQuestion(const std::string qdomain, const std::string& qtype, const std::string& qclass);
    void addQuestion(const std::string qdomain, unsigned qtype, unsigned qclass);

    //! Adds a RR
    void addRR(DnsPacket::RecordSection section, const std::string rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata);
    void addRR(DnsPacket::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const std::string& rdata);
    void addRR(DnsPacket::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen);
};


#endif
