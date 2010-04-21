
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dns_header.hpp"
#include "dns_question.hpp"
#include "rr.hpp"
#include "tokenizer.hpp"

class DnsPacket {
    int _socket;
    struct sockaddr_in _sin;
    struct sockaddr_in _din;
public:
    struct iphdr ip_hdr;
    struct udphdr udp_hdr;

    DnsHeader dns_hdr;
    
    DnsQuestion question;
    
    std::vector<ResourceRecord> answers;
    
    std::vector<ResourceRecord> authoritative;
    
    std::vector<ResourceRecord> additionals;
    
    DnsPacket();
    
    std::string data() const;
    
    void sendNet();
};

std::string convertDomain(const std::string& s);

#endif
