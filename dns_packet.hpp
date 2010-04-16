
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dns_header.hpp"
#include "dns_question.hpp"

class DnsPacket {
    int _socket;
    struct sockaddr_in _sin;
    struct sockaddr_in _din;
public:
    struct iphdr ip_hdr;
    struct udphdr udp_hdr;

    DnsHeader dns_hdr;
    
    DnsQuestion question;
    
    //vector<DnsAnswer> answers;
    
    //vector<DnsAdditional> additionals;
    
    //vector<DnsAuthoritative> autoritative;
    
    DnsPacket();
    
    std::string data() const;
    
    void send();
};

#endif
