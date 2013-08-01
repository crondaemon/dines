
#include <dns_packet.hpp>

#include <in_cksum.hpp>
#include <debug.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iostream>

using namespace std;

extern ostream* theLog;

void DnsPacket::socketCreate()
{
    int on = 1;

    _socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (_socket == -1) {
        stringstream ss;
        ss << __func__;
        ss << ": socket creation error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }

    if (setsockopt(_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
        throw runtime_error(string(__func__) + ": unable to set option IP_HDRINCL");

     memset(&_sin, 0x0, sizeof(_sin));
    _sin.sin_family = AF_INET;

    memset(&_din, 0x0, sizeof(_din));
    _din.sin_family = AF_INET;

    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
    ip_hdr.tos = 16;
    ip_hdr.tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip_hdr.id = 0xbeef;
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = IPPROTO_UDP;
    ip_hdr.check = 0;
    ip_hdr.daddr = 0;
    ip_hdr.saddr = 0;

    udp_hdr.source = 0;
    udp_hdr.dest = 0;
    udp_hdr.len = sizeof(udp_hdr);
    udp_hdr.check = 0;
}

DnsPacket::DnsPacket()
{

}

string DnsPacket::data() const
{
    string out = "";

    out += dnsHdr.data();
    out += question.data();

    for (vector<ResourceRecord>::const_iterator itr = answers.begin();
            itr != answers.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = authoritative.begin();
            itr != authoritative.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = additionals.begin();
            itr != additionals.end(); ++itr)
        out += itr->data();

    return out;
}

void DnsPacket::doUdpCksum()
{
    string dns = data();

    struct pseudo {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } phdr;

    phdr.saddr = this->ip_hdr.saddr;
    phdr.daddr = this->ip_hdr.daddr;
    phdr.zero = 0;
    phdr.proto = this->ip_hdr.protocol;
    phdr.len = this->udp_hdr.len;

    this->udp_hdr.check = 0;

//    printf("\n\n");
//    PRINT_HEX(&phdr, sizeof(struct pseudo), '\0');
//    PRINT_HEX(&this->udp_hdr, sizeof(struct udphdr), '\0');
//    PRINT_HEX(dns.c_str(), dns.length(), '\0');
//    printf("\n\n");

    char* temp = (char*)malloc(
        sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length());

    memcpy(temp, &phdr, sizeof(phdr));
    memcpy(temp + sizeof(phdr), &this->udp_hdr, sizeof(struct udphdr));
    memcpy(temp + sizeof(phdr) + sizeof(struct udphdr), dns.c_str(), dns.length());
    udp_hdr.check = in_cksum((u_short*)temp,
        sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length());

    free(temp);
}

void DnsPacket::sendNet()
{
    this->socketCreate();

    // Sanity checks

    if (ip_hdr.daddr == 0)
        throw runtime_error("You must specify destination ip (--dst-ip)");

    // Set L3/L4
    _sin.sin_port = udp_hdr.source;
    _sin.sin_addr.s_addr = ip_hdr.saddr;

    _din.sin_port = udp_hdr.dest;
    _din.sin_addr.s_addr = ip_hdr.daddr;

    if (connect(_socket, (struct sockaddr*)&_din, sizeof(_din)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": connect error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }

    if (ip_hdr.saddr == 0) {
        struct sockaddr_in sa;
        unsigned sa_len = sizeof(sa);
        getsockname(_socket, (struct sockaddr*)&sa, &sa_len);
        //printf("LOCAL IS %s\n", inet_ntop(AF_INET, &sa.sin_addr.s_addr, (char*)malloc(100), 100));
        this->ip_hdr.saddr = sa.sin_addr.s_addr;
    }

    if (udp_hdr.source == 0)
        udp_hdr.source = rand() % 0xFFFF;
    if (udp_hdr.dest == 0)
        udp_hdr.dest = htons(53); // put 53 if no port specified

    if (dnsHdr.txid == 0)
        dnsHdr.txid = rand() % 0xFFFF;
    if (question.qdomain().size() == 1)
        throw runtime_error("You must specify DNS question (--question)");

    // Create output to send
    string output;
    string dns_dgram = this->data();

    // Adjust lenghts
    udp_hdr.len = htons(sizeof(udp_hdr) + dns_dgram.length());
    ip_hdr.tot_len = htons(sizeof(ip_hdr) + sizeof(udp_hdr) + dns_dgram.length());

    // Calculate udp checksum
    doUdpCksum();

    output += string((char*)&ip_hdr, sizeof(ip_hdr));
    output += string((char*)&udp_hdr, sizeof(udp_hdr));
    output += dns_dgram;

    if (send(_socket, output.data(), output.length(), 0) < 0) {
        if (errno == 22) {
            cout << "Invalid parameter (probably fuzzer is shaking it).\n";
        } else {
            stringstream ss;
            ss << "sendto() error: ";
            ss << strerror(errno);
            throw runtime_error(ss.str());
        }
    }
}

string DnsPacket::ipFrom() const
{
    char buf[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &this->_sin.sin_addr.s_addr, buf, INET_ADDRSTRLEN))
        throw runtime_error("Error converting address");

    return string(buf);
}

string DnsPacket::ipTo() const
{
    char buf[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &this->_din.sin_addr.s_addr, buf, INET_ADDRSTRLEN))
        throw runtime_error("Error converting address");

    return string(buf);
}

string DnsPacket::to_string() const
{
    string s;

    s += "[" + this->ipFrom();
    s += " -> ";
    s += this->ipTo() + "]";

    return s;
}

void DnsPacket::addQuestion(const std::string& qdomain, const std::string& qtype, const std::string& qclass)
{
    dnsHdr.nrecord[DnsHeader::R_QUESTION]++;
    question = DnsQuestion(qdomain, qtype, qclass);
}

void DnsPacket::addQuestion(const std::string& qdomain, unsigned qtype, unsigned qclass)
{
    dnsHdr.nrecord[DnsHeader::R_QUESTION]++;
    question = DnsQuestion(qdomain, qtype, qclass);
}

void DnsPacket::addRR(DnsHeader::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen)
{
    string rd(rdata, rdatalen);
    addRR(section, rrDomain, rrType, rrClass, ttl, rd);
}

void DnsPacket::addRR(DnsHeader::RecordSection section, const std::string rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata)
{
    unsigned type = atoi(rrType.data());
    unsigned klass = atoi(rrClass.data());
    unsigned int_ttl = atoi(ttl.data());

    addRR(section, rrDomain, type,
    klass, int_ttl, rdata);
}

void DnsPacket::addRR(DnsHeader::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const std::string& rdata)
{
    std::vector<ResourceRecord> *rrPtr;

    switch (section) {
        case DnsHeader::R_ANSWER:
            rrPtr = &answers;
            break;
        case DnsHeader::R_AUTHORITATIVE:
            rrPtr = &authoritative;
            break;
        case DnsHeader::R_ADDITIONAL:
            rrPtr = &additionals;
            break;
        default:
            throw runtime_error("Unexpected section");
    }

    ResourceRecord rr(rrDomain, rrType, rrClass, ttl, rdata);
    dnsHdr.nrecord[section]++;
    rrPtr->push_back(rr);
}
