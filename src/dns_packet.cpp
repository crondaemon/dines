
#include <dns_packet.hpp>

#include <debug.hpp>
#include <utils.hpp>

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
#include <sstream>
#include <ifaddrs.h>
#include <netdb.h>

using namespace std;

DnsPacket::DnsPacket()
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

    _log = NULL;

    _spoofing = false;
    _packets = 1;
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

    if (!_question.empty())
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

    // Now the internet checksum
    int sum = 0;
    u_short *w = (u_short*)temp;
    int nleft = sizeof(struct pseudo) + sizeof(struct udphdr) + dns.length();

    _udpHdr.check = 0;

    while (nleft > 1)  {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1) {
      *(u_char *)(&_udpHdr.check) = *(u_char *)w;
      sum += _udpHdr.check;
    }

    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    _udpHdr.check = ~sum;                   /* truncate to 16 bits */

    delete temp;
}

void DnsPacket::_getFirstIP()
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1)
        BASIC_EXCEPTION_THROW("getifaddrs");

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET && string(ifa->ifa_name) != "lo") {
            _ipHdr.saddr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
            break;
        }
    }
}

void DnsPacket::_socketCreate()
{
    if (_ipHdr.saddr == 0)
        this->_getFirstIP();

    if (_udpHdr.source == 0)
        _udpHdr.source = rand();
    if (_udpHdr.dest == 0)
        _udpHdr.dest = htons(53); // put 53 if no port specified

    if (_dnsHdr.txid() == 0)
        _dnsHdr.txid(rand());

    if (_spoofing)
        _socketCreateRaw();
    else
        _socketCreateUdp();
}

void DnsPacket::_socketCreateRaw()
{
    int on = 1;

    _socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (_socket == -1)
        BASIC_EXCEPTION_THROW("socket");

    if (setsockopt(_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
        BASIC_EXCEPTION_THROW("setsockopt");

    // Set L3/L4
    struct sockaddr_in sin;
    memset(&sin, 0x0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = _udpHdr.dest;
    sin.sin_addr.s_addr = _ipHdr.daddr;

    if (connect(_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0)
        BASIC_EXCEPTION_THROW("connect");
}

string DnsPacket::_outputPackRaw(bool doCksum)
{
    // Create output to send
    string output;
    string dns_dgram = this->data();

    // ip id
    _ipHdr.id = rand();

    // Adjust lenghts
    _udpHdr.len = htons(sizeof(_udpHdr) + dns_dgram.length());
    _ipHdr.tot_len = htons(sizeof(_ipHdr) + sizeof(_udpHdr) + dns_dgram.length());

    // Calculate udp checksum
    if (doCksum)
        doUdpCksum();

    output += string((char*)&_ipHdr, sizeof(_ipHdr));
    output += string((char*)&_udpHdr, sizeof(_udpHdr));
    output += dns_dgram;

    return output;
}

string DnsPacket::_outputPackUdp()
{
    return this->data();
}

string DnsPacket::_outputPack(bool doCksum)
{
    if (_spoofing)
        return _outputPackRaw(doCksum);
    else
        return _outputPackUdp();
}

void DnsPacket::_socketCreateUdp()
{
    _socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (_socket == -1)
        BASIC_EXCEPTION_THROW("socket");

    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = _udpHdr.source;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(_socket, (struct sockaddr *)&sa, sizeof(struct sockaddr)) == -1)
        BASIC_EXCEPTION_THROW("bind");

    int opt = 1;
    if (setsockopt(_socket, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
        BASIC_EXCEPTION_THROW("setsockopt");
}

void DnsPacket::sendNet(bool doCksum)
{
    int ret;
    string api;

    // the remote/source sockaddr is put here
    struct sockaddr_in peeraddr;
    memset(&peeraddr, 0, sizeof(struct sockaddr_in));

    struct msghdr mh;

    if (_socket == -1)
        _socketCreate();

    string output = _outputPack(doCksum);

    if (_log)
        _log(this->to_string());

    mh.msg_name = &peeraddr;
    mh.msg_namelen = sizeof(peeraddr);

    if (!_spoofing) {
        struct iovec iov[1];
        iov[0].iov_base = (void*)output.data();
        iov[0].iov_len = output.size();

        peeraddr.sin_family = AF_INET;
        peeraddr.sin_port = _udpHdr.dest;
        peeraddr.sin_addr.s_addr = _ipHdr.daddr;

        mh.msg_iov = iov;
        mh.msg_iovlen = 1;

        mh.msg_control = 0;
        mh.msg_controllen = 0;

        ret = sendmsg(_socket, &mh, 0);
        api = "sendmsg()";
    } else {
        ret = send(_socket, output.data(), output.size(), 0);
        api = "send()";
    }

    if (ret < 0) {
        if (_log && errno == 22) {
            _log("Invalid parameter (probably fuzzer is shaking it)");
        } else {
            BASIC_EXCEPTION_THROW(api);
        }
    }

    // When not spoofing we have to get the packet back
    if (!_spoofing) {
        DnsPacket p;

        // Control buffer
        char cmbuf[0x100];

        struct iovec iov[1];

        iov[0].iov_base = (void*)malloc(1000);
        iov[0].iov_len = 1000;

        mh.msg_iov = iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cmbuf;
        mh.msg_controllen = sizeof(cmbuf);

        // Get the response
        if (recvmsg(_socket, &mh, 0) == -1)
            BASIC_EXCEPTION_THROW("recvmsg");

        // Parse the packet into a DnsPacket
        p.parse((char*)mh.msg_iov[0].iov_base);
        p.ipFrom(peeraddr.sin_addr.s_addr);
        p.sport(ntohs(peeraddr.sin_port));
        p.dport(ntohs(_udpHdr.source));

        // Get a control buffer and get destination ip from it
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
            // ignore the control headers that don't match what we want
            if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_PKTINFO) {
                continue;
            }
            struct in_pktinfo *pi = (struct in_pktinfo*)CMSG_DATA(cmsg);
            p.ipTo(pi->ipi_spec_dst.s_addr);
        }

        // Print the result
        if (_log)
            _log(string("Received ") + p.to_string());

        free(iov[0].iov_base);
    }
    _packets--;
}

string DnsPacket::ipFrom() const
{
    char buf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &_ipHdr.saddr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string DnsPacket::ipTo() const
{
    char buf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &_ipHdr.daddr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string DnsPacket::to_string(bool dnsonly) const
{
    string s;

    if (dnsonly == false) {
        s += this->ipFrom() + ":" + std::to_string(this->sport());
        s += " -> ";
        s += this->ipTo() + ":" + std::to_string(this->dport());
        s += " ";
    }

    s += "txid: 0x" + Dines::toHex(_dnsHdr.txid());

    s += isQuestion() ? " Q " : " R ";
    if (!_question.empty())
        s += "[Question:" + _question.to_string() + "]";

    if (_answers.size() > 0) {
        s += "[Answers:";
        for (vector<ResourceRecord>::const_iterator itr = _answers.begin();
                itr != _answers.end(); ++itr) {
            s += itr->to_string() + ",";
        }
        s.pop_back();
        s += "]";
    }

    if (_authorities.size() > 0) {
        s += "[Authorities:";
        for (vector<ResourceRecord>::const_iterator itr = _authorities.begin();
                itr != _authorities.end(); ++itr) {
            s += itr->to_string() + ",";
        }
        s.pop_back();
        s += "]";
    }

    if (_additionals.size() > 0) {
        s += "[Additionals:";
        for (vector<ResourceRecord>::const_iterator itr = _additionals.begin();
                itr != _additionals.end(); ++itr) {
            s += itr->to_string() + ",";
        }
        s.pop_back();
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

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const ResourceRecord& rr, bool counter_increment)
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
            throw runtime_error("Unexpected section " + std::to_string(section));
    }

    if (counter_increment)
        _dnsHdr.nRecordAdd(section, 1);

    rrPtr->push_back(rr);
    isQuestion(false);
    return rrPtr->front();
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const char* rdata, unsigned rdatalen,
        bool counter_increment)
{
    string rd(rdata, rdatalen);
    return addRR(section, rrDomain, rrType, rrClass, ttl, rd);
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string rrDomain,
        const std::string& rrType, const std::string& rrClass, const std::string& ttl,
        const std::string& rdata, bool counter_increment)
{
    unsigned type = Dines::stringToQtype(rrType);
    unsigned klass = Dines::stringToQclass(rrClass);
    unsigned int_ttl = stoul(ttl.data());

    return addRR(section, rrDomain, type, klass, int_ttl, rdata);
}

ResourceRecord& DnsPacket::addRR(Dines::RecordSection section, const std::string& rrDomain,
        unsigned rrType, unsigned rrClass, unsigned ttl, const std::string& rdata, bool counter_increment)
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

void DnsPacket::question(const DnsQuestion& q)
{
    _dnsHdr.nRecord(Dines::R_QUESTION, 1);
    _question = q;
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

void DnsPacket::ipFrom(uint32_t ip)
{
    _spoofing = true;
    _ipHdr.saddr = ip;
}

void DnsPacket::ipFrom(string ip_from)
{
    _spoofing = true;
    _ipHdr.saddr = inet_addr(ip_from.data());
}

void DnsPacket::ipTo(string ip_to)
{
    _ipHdr.daddr = inet_addr(ip_to.data());
}

void DnsPacket::ipTo(uint32_t ip)
{
    _spoofing = true;
    _ipHdr.daddr = ip;
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
    _udpHdr.source = htons(stoul(sport.data()));
}

void DnsPacket::dport(string dport)
{
    _udpHdr.dest = htons(stoul(dport.data()));
}

uint16_t DnsPacket::txid() const
{
    return _dnsHdr.txid();
}

void DnsPacket::txid(string txid)
{
    _dnsHdr.txid(stoul(txid.data()));
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
        _udpHdr.source = rand();
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

void DnsPacket::dnsHdr(const DnsHeader& h)
{
    _dnsHdr = h;
}

DnsHeader& DnsPacket::dnsHdr()
{
    return _dnsHdr;
}

void DnsPacket::fuzzSrcIp()
{
    _fuzzSrcIp = true;
}

void DnsPacket::fuzzSport()
{
    _fuzzSport = true;
}

void DnsPacket::logger(Dines::LogFunc l)
{
    _log = l;
}

void DnsPacket::packets(unsigned num)
{
    if (num == 0)
        _packets = 0xFFFFFFFF;
    else
        _packets = num;
}

unsigned DnsPacket::packets() const
{
    return _packets;
}

string DnsPacket::packetsStr() const
{
    if (_packets == 0xFFFFFFFF) {
        return "infinite";
    } else {
        return std::to_string(_packets);
    }
}

bool DnsPacket::invalid() const
{
    return (invalidMsg() == "" ? false : true);
}

string DnsPacket::invalidMsg() const
{
    if (_ipHdr.daddr == 0)
        return "You must specify destination ip";

    return "";
}

void DnsPacket::parse(char* buf)
{
    unsigned i;
    unsigned offset = 0;
    offset += _dnsHdr.parse(buf, offset);
    offset += _question.parse(buf, offset);

    // Parse answers
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_ANSWER); i++) {
        ResourceRecord rr;
        offset += rr.parse(buf, offset);
        this->addRR(Dines::R_ANSWER, rr, false);
    }

    // Parse auth
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_AUTHORITIES); i++) {
        ResourceRecord rr;
        offset += rr.parse(buf, offset);
        this->addRR(Dines::R_AUTHORITIES, rr, false);
    }

    // Parse add
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_ADDITIONAL); i++) {
        ResourceRecord rr;
        offset += rr.parse(buf, offset);
        this->addRR(Dines::R_ADDITIONAL, rr, false);
    }
}

void DnsPacket::sport(uint16_t sport)
{
    _udpHdr.source = htons(sport);
}

void DnsPacket::dport(uint16_t dport)
{
    _udpHdr.dest = htons(dport);
}
