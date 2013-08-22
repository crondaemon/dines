
#include <dns_packet.hpp>

#include <in_cksum.hpp>
#include <debug.hpp>
#include <convert.hpp>

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <stdlib.h>

using namespace std;

DnsPacket::DnsPacket(Dines::LogFunc l)
{
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

    _socket = -1;
    _recvSocket = -1;

    srand(time(NULL));

    _fuzzSrcIp = false;
    _fuzzSport = false;

    _log = l;

    if (_log != NULL)
        _log("DnsPacket created");
}

DnsPacket::DnsPacket(const DnsPacket& p)
{
    *this = p;
}

DnsPacket& DnsPacket::operator=(const DnsPacket& p)
{
    _socket = p._socket;
    _recvSocket = p._recvSocket;
    _ipHdr = p._ipHdr;
    _udpHdr = p._udpHdr;
    _dnsHdr = p._dnsHdr;
    _question = p._question;
    _answers = p._answers;
    _authorities = p._authorities;
    _additionals = p._additionals;
    _fuzzSrcIp = p._fuzzSrcIp;
    _fuzzSport = p._fuzzSport;
    _log = p._log;

    return *this;
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

    phdr.saddr = _ipHdr.saddr;
    phdr.daddr = _ipHdr.daddr;
    phdr.zero = 0;
    phdr.proto = _ipHdr.protocol;
    phdr.len = _udpHdr.len;

    _udpHdr.check = 0;

    char* temp = new char[sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length()];

    memcpy(temp, &phdr, sizeof(phdr));
    memcpy(temp + sizeof(phdr), &this->_udpHdr, sizeof(struct udphdr));
    memcpy(temp + sizeof(phdr) + sizeof(struct udphdr), dns.c_str(), dns.length());
    _udpHdr.check = in_cksum((u_short*)temp,
        sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length());

    delete temp;
}

void DnsPacket::_socketCreate()
{
    if (_socket > 0) {
        return;
    }

    int on = 1;
    struct sockaddr_in servaddr;

    // Sanity checks

    if (_ipHdr.daddr == 0)
        throw runtime_error("You must specify destination ip (--dst-ip)");

    if (_udpHdr.source == 0)
        _udpHdr.source = rand() % 0xFFFF;
    if (_udpHdr.dest == 0)
        _udpHdr.dest = htons(53); // put 53 if no port specified

    if (_dnsHdr.txid() == 0)
        _dnsHdr.txid(rand() % 0xFFFF);

    _socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (_socket == -1)
        throw runtime_error(string(__func__) + ": socket creation error: " + string(strerror(errno)));

    if (setsockopt(_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
        throw runtime_error(string(__func__) + ": unable to set option _IPHDRINCL");

    // Set L3/L4
    struct sockaddr_in sin;
    memset(&sin, 0x0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = _udpHdr.dest;
    sin.sin_addr.s_addr = _ipHdr.daddr;

    if (connect(_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0)
        throw runtime_error(string(__func__) + "::connect() (" + string(strerror(errno)) + ")");

    if (_ipHdr.saddr == 0) {
        // we are not spoofing. Set the source address from localhost
        struct sockaddr_in sa;
        unsigned sa_len = sizeof(sa);
        getsockname(_socket, (struct sockaddr*)&sa, &sa_len);
        _ipHdr.saddr = sa.sin_addr.s_addr;

        _recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (_recvSocket == -1)
            throw runtime_error("Can't create listening socket");

        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = _udpHdr.source;

        if (_log) {
            char buf[10];
            snprintf(buf, 10, "%u", htons(_udpHdr.source));
            _log("Creating listening socket on port " + string(buf));
        }

        if (bind(_recvSocket, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 )
            throw runtime_error("Can't bind() listening socket");
    }
}

void DnsPacket::sendNet(bool doCksum)
{
    _socketCreate();

    // Create output to send
    string output;
    string dns_dgram = this->data();

    // ip id
    _ipHdr.id = rand() % 0xFFFF;

    // Adjust lenghts
    _udpHdr.len = htons(sizeof(_udpHdr) + dns_dgram.length());
    _ipHdr.tot_len = htons(sizeof(_ipHdr) + sizeof(_udpHdr) + dns_dgram.length());

    // Calculate udp checksum
    if (doCksum)
        doUdpCksum();

    output += string((char*)&_ipHdr, sizeof(_ipHdr));
    output += string((char*)&_udpHdr, sizeof(_udpHdr));
    output += dns_dgram;

    if (_log)
        _log(this->to_string());

    if (send(_socket, output.data(), output.length(), 0) < 0) {
        if (errno == 22) {
            cout << "Invalid parameter (probably fuzzer is shaking it).\n";
        } else {
            throw runtime_error("send() error: " + string(strerror(errno)));
        }
    }
}

string DnsPacket::ipFrom() const
{
    char buf[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &_ipHdr.saddr, buf, INET_ADDRSTRLEN))
        throw runtime_error("Error converting address");

    return string(buf);
}

string DnsPacket::ipTo() const
{
    char buf[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &_ipHdr.daddr, buf, INET_ADDRSTRLEN))
        throw runtime_error("Error converting address");

    return string(buf);
}

string DnsPacket::to_string() const
{
    string s;

    s += this->ipFrom() + ":" + Dines::convertInt<uint16_t>(this->sport());
    s += " -> ";
    s += this->ipTo() + ":" + Dines::convertInt<uint16_t>(this->dport());
    s += " txid: " + Dines::convertInt<uint16_t>(_dnsHdr.txid());

    if (isQuestion())
        s += " Q ";
    else
        s += " R ";

    if (_question != DnsQuestion()) {
        s += "[Question:" + _question.to_string() + "]";
    }

    if (_answers.size() > 0) {
        s += "[Answers:";
        for (vector<ResourceRecord>::const_iterator itr = _answers.begin();
                itr != _answers.end(); ++itr) {
            s += itr->to_string();
        }
        s += "]";
    }

    if (_authorities.size() > 0) {
        s += "[Authorities:";
        for (vector<ResourceRecord>::const_iterator itr = _authorities.begin();
                itr != _authorities.end(); ++itr) {
            s += itr->to_string();
        }
        s += "]";
    }

    if (_additionals.size() > 0) {
        s += "[Additionals:";
        for (vector<ResourceRecord>::const_iterator itr = _additionals.begin();
                itr != _additionals.end(); ++itr) {
            s += itr->to_string();
        }
        s += "]";
    }

    return s;
}

DnsQuestion& DnsPacket::addQuestion(const std::string qdomain, const std::string& qtype,
        const std::string& qclass)
{
    _dnsHdr.nRecordAdd(Dines::R_QUESTION, 1);
    _question = DnsQuestion(qdomain, qtype, qclass);
    return _question;
}

DnsQuestion& DnsPacket::addQuestion(const std::string qdomain, unsigned qtype, unsigned qclass)
{
    _dnsHdr.nRecordAdd(Dines::R_QUESTION, 1);
    _question = DnsQuestion(qdomain, qtype, qclass);
    return _question;
}

DnsQuestion& DnsPacket::addQuestion(const DnsQuestion& q)
{
    _question = q;
    _dnsHdr.nRecord(Dines::R_QUESTION, 1);
    return _question;
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen)
{
    string rd(rdata, rdatalen);
    return addRR(section, rrDomain, rrType, rrClass, ttl, rd);
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string rrDomain,
        const std::string& rrType, const std::string& rrClass, const std::string& ttl,
        const std::string& rdata)
{
    unsigned type = Dines::stringToQtype(rrType);
    unsigned klass = Dines::stringToQclass(rrClass);
    unsigned int_ttl = atoi(ttl.data());

    string localrdata = rdata;

    return addRR(section, rrDomain, type, klass, int_ttl, localrdata);
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const std::string& rdata)
{
    ResourceRecord rr(rrDomain, rrType, rrClass, ttl, rdata);
    return addRR(section, rr);
}

bool DnsPacket::isRecursive() const
{
    return _dnsHdr.isRecursive();
}

void DnsPacket::isRecursive(const bool isRecursive)
{
    _dnsHdr.rd(false);
}

bool DnsPacket::isQuestion() const
{
    return _dnsHdr.isQuestion();
}

uint16_t DnsPacket::nRecord(Dines::RecordSection section) const
{
    return _dnsHdr.nRecord(section);
}

DnsQuestion& DnsPacket::question()
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
    return _dnsHdr.txid();
}

void DnsPacket::txid(string txid)
{
    _dnsHdr.txid(atoi(txid.data()));
}

void DnsPacket::txid(uint16_t txid)
{
    _dnsHdr.txid(txid);
}

void DnsPacket::nRecord(Dines::RecordSection section, uint16_t value)
{
    if (_log) {
        char sect[10];
        char val[11];
        snprintf(sect, 10, "%u", section);
        snprintf(val, 11, "%u", value);
        _log("Setting record section " + string(sect) + " to " + string(val));
    }

    _dnsHdr.nRecord(section, value);
}

void DnsPacket::isQuestion(bool isQuestion)
{
    _dnsHdr.isQuestion(isQuestion);
}

void DnsPacket::fuzz()
{
    if (_fuzzSrcIp) {
        _ipHdr.saddr = rand();
    }

    if (_fuzzSport) {
        _udpHdr.source = rand() % 65535;
    }

    _dnsHdr.fuzz();
    _question.fuzz();
    for (vector<ResourceRecord>::iterator itr = _answers.begin(); itr != _answers.end();
            ++itr) {
        itr->fuzz();
    }
    for (vector<ResourceRecord>::iterator itr = _additionals.begin(); itr != _additionals.end();
            ++itr) {
        itr->fuzz();
    }
    for (vector<ResourceRecord>::iterator itr = _authorities.begin(); itr != _authorities.end();
            ++itr) {
        itr->fuzz();
    }
}

DnsHeader& DnsPacket::dnsHdr()
{
    return _dnsHdr;
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const ResourceRecord& rr)
{
    std::vector<ResourceRecord> *rrPtr;

    switch (section) {
        case Dines::R_ANSWER:
            rrPtr = &_answers;
            break;
        case Dines::R_AUTHORITIES:
            rrPtr = &_authorities;
            break;
        case Dines::R_ADDITIONAL:
            rrPtr = &_additionals;
            break;
        default:
            throw runtime_error("Unexpected section");
    }

    _dnsHdr.nRecordAdd(section, 1);
    rrPtr->push_back(rr);
    isQuestion(false);
    return rrPtr->front();
}

void DnsPacket::fuzzSrcIp()
{
    _fuzzSrcIp = true;
}

void DnsPacket::fuzzSport()
{
    _fuzzSport = true;
}

void DnsPacket::setLogger(Dines::LogFunc l)
{
    _log = l;
}
