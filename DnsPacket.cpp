
#include "DnsPacket.hpp"

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

DnsPacket::DnsPacket()
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
    _sin.sin_port = htons(53);
    _sin.sin_addr.s_addr = inet_addr("1.2.3.4");

    _din.sin_family = AF_INET;
    _din.sin_port = htons(53);
    _din.sin_addr.s_addr = inet_addr("2.3.4.5");


    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
    ip_hdr.tos = 16;
    ip_hdr.tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip_hdr.id = htons(53);
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = IPPROTO_UDP;
    ip_hdr.check = 0;
    ip_hdr.daddr = inet_addr("1.2.3.4");
    ip_hdr.saddr = inet_addr("2.3.4.5");
    
    udp_hdr.source = htons(10);
    udp_hdr.dest = htons(53);
    udp_hdr.len = sizeof(udp_hdr);
    udp_hdr.check = 0;
    
    if (connect(_socket, (struct sockaddr*)&_din, sizeof(_din)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": connect error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }
}

string DnsPacket::data() const
{
    string out = "";
    
    out += dns_hdr.data();
    out += question.data();
    
    return out;
}

void DnsPacket::send()
{
    string output;
    string dns_dgram = data();
    
    udp_hdr.len = htons(sizeof(udp_hdr) + dns_dgram.length());
    ip_hdr.tot_len = htons(sizeof(ip_hdr) + sizeof(udp_hdr) + dns_dgram.length() + 1000);
    
    output += string((char*)&ip_hdr, sizeof(ip_hdr));
    output += string((char*)&udp_hdr, sizeof(udp_hdr));
    output += dns_dgram;
    
    if (sendto(_socket, output.data(), output.length(), 0, (struct sockaddr *)&_sin, sizeof(_sin)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": sendto() error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }
}
