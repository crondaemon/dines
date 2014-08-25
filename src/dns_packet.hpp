
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
#include <dinestypes.hpp>

class DnsPacket {
    int _socket;
    int _recvSocket;

    //! Creates the socket
    void _socketCreate();

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

    bool _fuzzSrcIp;

    bool _fuzzSport;

    Dines::LogFunc _log;

    unsigned _datagrams;

    //! Perform the internet checksum
    void inCksum();
public:
    //! Constructor
    DnsPacket(Dines::LogFunc l = NULL);
    DnsPacket(const DnsPacket& p);

    DnsPacket& operator=(const DnsPacket& p);

    DnsHeader& dnsHdr();
    DnsQuestion& question();
    ResourceRecord& rr(Dines::RecordSection section, unsigned n);

    //! Compute the UDP checksum
    void doUdpCksum();

    //! Raw data getter
    std::string data() const;

    //! Sends the packet into the network
    void sendNet(bool doCksum = true);

    //! to_string
    std::string to_string(bool dnsonly = false) const;

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

    void txid(uint16_t txid);

    //! Nrecord
    uint16_t nRecord(Dines::RecordSection section) const;

    void nRecord(Dines::RecordSection section, uint16_t value);

    //! Return true is packet has recursion activated
    bool isRecursive() const;

    void isRecursive(const bool isRecursive);

    void isQuestion(bool isQuestion);

    //! Return true if packet is a question
    bool isQuestion() const;

    const ResourceRecord& answers(unsigned n) const;
    const ResourceRecord& additionals(unsigned n) const;
    const ResourceRecord& authorities(unsigned n) const;

    //! Adds a question
    DnsQuestion& addQuestion(const std::string qdomain, const std::string& qtype,
        const std::string& qclass);
    DnsQuestion& addQuestion(const std::string qdomain, unsigned qtype, unsigned qclass);
    DnsQuestion& addQuestion(const DnsQuestion& q);

    //! Adds a RR
    ResourceRecord& addRR(Dines::RecordSection section, const std::string rrDomain,
        const std::string& rrType, const std::string& rrClass, const std::string& ttl,
        const std::string& rdata);

    //! Adds a RR
    ResourceRecord& addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const std::string& rdata);

    //! Adds a RR
    ResourceRecord& addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const char* rdata,
        unsigned rdatalen);

    //! Adds a RR
    ResourceRecord& addRR(Dines::RecordSection section, const ResourceRecord& rr);

    //! Run the fuzzer
    void fuzz();

    //! Set fuzzing for src ip
    void fuzzSrcIp();

    //! Set fuzzing for dst ip
    void fuzzSport();

    //! Set the logger
    void logger(Dines::LogFunc l);

    //! Sets how many packets are to send
    void packets(unsigned num);

    //! Return the number of packets left
    unsigned packets() const;

    //! Return the number of packets left (as string)
    std::string packetsStr() const;

    //! Return true if the packet is invalid
    bool invalid() const;

    //! Return a message that describe why a packet is invalid, empty string otherwise
    std::string invalidMsg() const;
};


#endif
