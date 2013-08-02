
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
#include <stdlib.h>

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
        throw runtime_error(string(__func__) + ": unable to set option _ipHdrINCL");

     memset(&_sin, 0x0, sizeof(_sin));
    _sin.sin_family = AF_INET;

    memset(&_din, 0x0, sizeof(_din));
    _din.sin_family = AF_INET;

    _ipHdr.ihl = 5;
    _ipHdr.version = 4;
    _ipHdr.tos = 16;
    _ipHdr.tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    _ipHdr.id = 0xbeef;
    _ipHdr.frag_off = 0;
    _ipHdr.ttl = 64;
    _ipHdr.protocol = IPPROTO_UDP;
    _ipHdr.check = 0;
    _ipHdr.daddr = 0;
    _ipHdr.saddr = 0;

    _udpHdr.source = 0;
    _udpHdr.dest = 0;
    _udpHdr.len = sizeof(_udpHdr);
    _udpHdr.check = 0;
}

DnsPacket::DnsPacket()
{

}

string DnsPacket::data() const
{
    string out = "";

    out += _dnsHdr.data();
    out += _question.data();

    for (vector<ResourceRecord>::const_iterator itr = _answers.begin();
            itr != _answers.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = _authorities.begin();
            itr != _authorities.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = _additionals.begin();
            itr != _additionals.end(); ++itr)
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

    phdr.saddr = this->_ipHdr.saddr;
    phdr.daddr = this->_ipHdr.daddr;
    phdr.zero = 0;
    phdr.proto = this->_ipHdr.protocol;
    phdr.len = this->_udpHdr.len;

    this->_udpHdr.check = 0;

//    printf("\n\n");
//    PRINT_HEX(&phdr, sizeof(struct pseudo), '\0');
//    PRINT_HEX(&this->_udpHdr, sizeof(struct udphdr), '\0');
//    PRINT_HEX(dns.c_str(), dns.length(), '\0');
//    printf("\n\n");

    char* temp = new char[sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length()];

    memcpy(temp, &phdr, sizeof(phdr));
    memcpy(temp + sizeof(phdr), &this->_udpHdr, sizeof(struct udphdr));
    memcpy(temp + sizeof(phdr) + sizeof(struct udphdr), dns.c_str(), dns.length());
    _udpHdr.check = in_cksum((u_short*)temp,
        sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length());

    delete temp;
}

void DnsPacket::sendNet()
{
    this->socketCreate();

    // Sanity checks

    if (_ipHdr.daddr == 0)
        throw runtime_error("You must specify destination ip (--dst-ip)");

    // Set L3/L4
    _sin.sin_port = _udpHdr.source;
    _sin.sin_addr.s_addr = _ipHdr.saddr;

    _din.sin_port = _udpHdr.dest;
    _din.sin_addr.s_addr = _ipHdr.daddr;

    if (connect(_socket, (struct sockaddr*)&_din, sizeof(_din)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": connect error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }

    if (_ipHdr.saddr == 0) {
        struct sockaddr_in sa;
        unsigned sa_len = sizeof(sa);
        getsockname(_socket, (struct sockaddr*)&sa, &sa_len);
        //printf("LOCAL IS %s\n", inet_ntop(AF_INET, &sa.sin_addr.s_addr, (char*)malloc(100), 100));
        this->_ipHdr.saddr = sa.sin_addr.s_addr;
    }

    if (_udpHdr.source == 0)
        _udpHdr.source = rand() % 0xFFFF;
    if (_udpHdr.dest == 0)
        _udpHdr.dest = htons(53); // put 53 if no port specified

    if (_dnsHdr.txid == 0)
        _dnsHdr.txid = rand() % 0xFFFF;
    if (_question.qdomain().size() == 1)
        throw runtime_error("You must specify DNS question (--question)");

    // Create output to send
    string output;
    string dns_dgram = this->data();

    // Adjust lenghts
    _udpHdr.len = htons(sizeof(_udpHdr) + dns_dgram.length());
    _ipHdr.tot_len = htons(sizeof(_ipHdr) + sizeof(_udpHdr) + dns_dgram.length());

    // Calculate udp checksum
    doUdpCksum();

    output += string((char*)&_ipHdr, sizeof(_ipHdr));
    output += string((char*)&_udpHdr, sizeof(_udpHdr));
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

void DnsPacket::addQuestion(const std::string qdomain, const std::string& qtype, const std::string& qclass)
{
    _dnsHdr.nrecord[DnsPacket::R_QUESTION]++;
    _question = DnsQuestion(qdomain, qtype, qclass);
}

void DnsPacket::addQuestion(const std::string qdomain, unsigned qtype, unsigned qclass)
{
    _dnsHdr.nrecord[DnsPacket::R_QUESTION]++;
    _question = DnsQuestion(qdomain, qtype, qclass);
}

void DnsPacket::addRR(DnsPacket::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen)
{
    string rd(rdata, rdatalen);
    addRR(section, rrDomain, rrType, rrClass, ttl, rd);
}

void DnsPacket::addRR(DnsPacket::RecordSection section, const std::string rrDomain, const std::string& rrType,
        const std::string& rrClass, const std::string& ttl, const std::string& rdata)
{
    unsigned type = atoi(rrType.data());
    unsigned klass = atoi(rrClass.data());
    unsigned int_ttl = atoi(ttl.data());

    addRR(section, rrDomain, type,
    klass, int_ttl, rdata);
}

void DnsPacket::addRR(DnsPacket::RecordSection section, const std::string& rrDomain, unsigned rrType,
        unsigned rrClass, unsigned ttl, const std::string& rdata)
{
    std::vector<ResourceRecord> *rrPtr;

    switch (section) {
        case DnsPacket::R_ANSWER:
            rrPtr = &_answers;
            break;
        case DnsPacket::R_AUTHORITIES:
            rrPtr = &_authorities;
            break;
        case DnsPacket::R_ADDITIONAL:
            rrPtr = &_additionals;
            break;
        default:
            throw runtime_error("Unexpected section");
    }

    ResourceRecord rr(rrDomain, rrType, rrClass, ttl, rdata);
    _dnsHdr.nrecord[section]++;
    rrPtr->push_back(rr);
}

bool DnsPacket::isRecursive() const
{
    return _dnsHdr.isRecursive();
}

bool DnsPacket::isQuestion() const
{
    return _dnsHdr.isQuestion();
}

uint16_t DnsPacket::nrecord(DnsPacket::RecordSection section) const
{
    return _dnsHdr.nrecord[section];
}

const DnsQuestion& DnsPacket::question() const
{
    return _question;
}

const ResourceRecord& DnsPacket::answers(unsigned n) const
{
    return _answers.at(n);
}

const ResourceRecord& DnsPacket::additionals(unsigned n) const
{
    return _additionals.at(n);
}

const ResourceRecord& DnsPacket::authorities(unsigned n) const
{
    return _authorities.at(n);
}

void DnsPacket::ipFrom(string ip_from)
{
    _ipHdr.saddr = inet_addr(ip_from.data());
}

void DnsPacket::ipTo(string ip_to)
{
    _ipHdr.daddr = inet_addr(ip_to.data());
}

uint16_t DnsPacket::sport() const
{
    return ntohs(_udpHdr.source);
}

uint16_t DnsPacket::dport() const
{
    return ntohs(_udpHdr.dest);
}

void DnsPacket::sport(string sport)
{
    _udpHdr.source = htons(atoi(sport.data()));
}

void DnsPacket::dport(string dport)
{
    _udpHdr.dest = htons(atoi(dport.data()));
}

uint16_t DnsPacket::txid() const
{
    return ntohs(_dnsHdr.txid);
}

void DnsPacket::txid(string txid)
{
    _dnsHdr.txid = htons(atoi(optarg));
}

void DnsPacket::nrecord(DnsPacket::RecordSection section, uint32_t value)
{
    _dnsHdr.nrecord[section] = value;
}

void DnsPacket::isQuestion(bool isQuestion)
{
    _dnsHdr.flags.qr = (isQuestion == true);
}
