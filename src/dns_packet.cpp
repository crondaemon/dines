
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
#include <resolv.h>
#include <unistd.h>

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
    _spoofing = p._spoofing;

    return *this;
}

string DnsPacket::data() const
{
    string out = _dnsHdr.data();

    if (!_question.empty()) {
        out += _question.data();
    }
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
        _udpHdr.source = Dines::random_16();
    if (_udpHdr.dest == 0)
        _udpHdr.dest = htons(53); // put 53 if no port specified

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
    _ipHdr.id = Dines::random_16();

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

    // Set a standard timeout (3 sec)
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        BASIC_EXCEPTION_THROW("setsockopt");
    }

    if (bind(_socket, (struct sockaddr *)&sa, sizeof(struct sockaddr)) == -1) {
        BASIC_EXCEPTION_THROW("bind");
    }

    int opt = 1;
    if (setsockopt(_socket, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
        BASIC_EXCEPTION_THROW("setsockopt");
}

DnsPacket* DnsPacket::sendNet(bool doCksum)
{
    int ret;
    string api;
    DnsPacket* p = NULL;

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
        api = "sendmsg";
    } else {
        ret = send(_socket, output.data(), output.size(), 0);
        api = "send";
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
        int len;
        p = new DnsPacket();

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
        len = recvmsg(_socket, &mh, 0);
        if (len == -1)
            BASIC_EXCEPTION_THROW("recvmsg");

        // Parse the packet into a DnsPacket
        p->parse((char*)mh.msg_iov[0].iov_base, len);
        p->from(peeraddr.sin_addr.s_addr);
        p->sport(ntohs(peeraddr.sin_port));
        p->dport(ntohs(_udpHdr.source));

        // Get a control buffer and get destination ip from it
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
            // ignore the control headers that don't match what we want
            if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_PKTINFO) {
                continue;
            }
            struct in_pktinfo *pi = (struct in_pktinfo*)CMSG_DATA(cmsg);
            p->to(pi->ipi_spec_dst.s_addr);
        }

        // Print the result
        if (_log)
            _log(string("Received ") + p->to_string());

        free(iov[0].iov_base);
    }
    _packets--;

    return p;
}

string DnsPacket::from() const
{
    char buf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &_ipHdr.saddr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string DnsPacket::to() const
{
    char buf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &_ipHdr.daddr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string DnsPacket::to_string(bool dnsonly) const
{
    string s;

    if (dnsonly == false) {
        s += this->from() + ":" + std::to_string(this->sport());
        s += " -> ";
        s += this->to() + ":" + std::to_string(this->dport());
        s += " ";
    }

    s += _dnsHdr.to_string();

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

    if (_log)
        _question.logger(_log);

    return _question;
}

DnsQuestion& DnsPacket::addQuestion(const std::string qdomain, unsigned qtype, unsigned qclass)
{
    return this->addQuestion(qdomain, std::to_string(qtype), std::to_string(qclass));
}

DnsQuestion& DnsPacket::addQuestion(const DnsQuestion& q)
{
    _question = q;
    if (_log)
        _question.logger(_log);
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
    ResourceRecord& newrr = rrPtr->front();
    isQuestion(false);
    if (_log)
        newrr.logger(_log);
    return newrr;
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

void DnsPacket::from(uint32_t ip_from)
{
    _spoofing = true;
    _ipHdr.saddr = ip_from;
}

void DnsPacket::from(string ip_from)
{
    _spoofing = true;
    _ipHdr.saddr = Dines::stringToIp32(ip_from);
}

void DnsPacket::to(string dest)
{
    try {
        _ipHdr.daddr = Dines::stringToIp32(dest);
        return;
    } catch(exception& e) {
        // Provided ip was not an ip. We try to resolve it into an ip
        if (res_init() == -1) {
            BASIC_EXCEPTION_THROW("res_init");
        }

        u_char ans[65535];

        int len = res_search(dest.data(), C_IN, T_A, ans, 65535);
        if (len == -1) {
            throw runtime_error("Can't resolve " + dest);
        }
        DnsPacket p;
        p.parse((char*)ans, len);
        _ipHdr.daddr = Dines::stringToIp32(p.answers(0).rData());
    }
}

void DnsPacket::to(uint32_t ip_to)
{
    _ipHdr.daddr = ip_to;
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

uint16_t DnsPacket::udpSum() const
{
    return ntohs(_udpHdr.check);
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
        _ipHdr.saddr = Dines::random_32();
    }

    if (_fuzzSport) {
        _udpHdr.source = Dines::random_16();
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
    _dnsHdr.logger(l);
    _question.logger(l);
    for (vector<ResourceRecord>::iterator itr = _answers.begin(); itr != _answers.end(); ++itr)
        itr->logger(l);
    for (vector<ResourceRecord>::iterator itr = _authorities.begin(); itr != _authorities.end(); ++itr)
        itr->logger(l);
    for (vector<ResourceRecord>::iterator itr = _additionals.begin(); itr != _additionals.end(); ++itr)
        itr->logger(l);
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

void DnsPacket::parse(char* buf, unsigned buflen)
{
    unsigned i;
    unsigned offset = 0;
    unsigned remaining = buflen;
    unsigned len;

    len = _dnsHdr.parse(buf, remaining, offset);
    offset += len;
    remaining -= len;

    len = _question.parse(buf, remaining, offset);
    offset += len;
    remaining -= len;

    // Parse answers
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_ANSWER); i++) {
        ResourceRecord rr;
        len = rr.parse(buf, remaining, offset);
        offset += len;
        remaining -= len;
        if (len > 0)
            this->addRR(Dines::R_ANSWER, rr, false);
    }

    // Parse auth
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_AUTHORITIES); i++) {
        ResourceRecord rr;
        len += rr.parse(buf, buflen - offset, offset);
        offset += len;
        remaining -= len;
        if (len > 0)
            this->addRR(Dines::R_AUTHORITIES, rr, false);
    }

    // Parse add
    for (i = 0; i < _dnsHdr.nRecord(Dines::R_ADDITIONAL); i++) {
        ResourceRecord rr;
        len = rr.parse(buf, buflen - offset, offset);
        offset += len;
        remaining -= len;
        if (len > 0)
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

void DnsPacket::clear()
{
    _dnsHdr.clear();
    _question.clear();

    for (vector<ResourceRecord>::iterator itr = _answers.begin(); itr != _answers.end(); ++itr)
        itr->clear();

    for (vector<ResourceRecord>::iterator itr = _authorities.begin(); itr != _authorities.end(); ++itr)
        itr->clear();

    for (vector<ResourceRecord>::iterator itr = _additionals.begin(); itr != _additionals.end(); ++itr)
        itr->clear();
}
