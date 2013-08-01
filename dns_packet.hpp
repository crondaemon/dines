
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>
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
public:
    //! Constructor
    DnsPacket();

    //! The fuzzer
    Fuzzer fuzzer;

    //! IP layer
    struct iphdr ip_hdr;

    //! UDP layer
    struct udphdr udp_hdr;

    //! DNS SECTION

    //! DNS header
    DnsHeader dnsHdr;

    //! DNS question
    DnsQuestion question;

    //! DNS answers
    std::vector<ResourceRecord> answers;

    //! DNS authoritative
    std::vector<ResourceRecord> authoritative;

    //! DNS additionals
    std::vector<ResourceRecord> additionals;

    //! Compute the UDP checksum
    void doUdpCksum();

    //! Raw data getter
    std::string data() const;

    //! Sends the packet into the network
    void sendNet();

    //! to_string
    std::string to_string() const;

    //! IP source as string
    std::string ipFrom() const;

    //! IP dest as string
    std::string ipTo() const;

    //! Adds a question
    void addQuestion(const std::string& qdomain, const std::string& qtype, const std::string& qclass);
    void addQuestion(const std::string& qdomain, unsigned qtype, unsigned qclass);

    //! Adds a RR
    void addRR(DnsHeader::RecordSection section, const std::string rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata);
    void addRR(DnsHeader::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const std::string& rdata);
    void addRR(DnsHeader::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen);
};


#endif
