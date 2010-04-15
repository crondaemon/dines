
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "DnsHeader.hpp"
#include "DnsQuestion.hpp"

class DnsPacket {
    int _socket;
    struct sockaddr_in _sin;
public:
    struct iphdr ip_hdr;
    struct udphdr udp_hdr;

    DnsHeader dns_hdr;
    
    DnsQuestion q;
    
    //vector<DnsAnswer> answers;
    
    //vector<DnsAdditional> additionals;
    
    //vector<DnsAuthoritative> autoritative;
    
    DnsPacket();
    
    std::string data() const;
    
    void send() const;
};

#endif
