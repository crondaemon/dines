
#include "dns_packet.hpp"

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

string DnsPacket::data() const
{
    string out = "";
    
    out += dns_hdr.data();
    out += question.data();
    
    return out;
}

void DnsPacket::send()
{
    // Sanity checks   
    if (udp_hdr.source == 0)
        udp_hdr.source = rand();
    if (ip_hdr.saddr == 0)
        ; // XXX
    if (udp_hdr.dest == 0)
        udp_hdr.dest = htons(53); // put 53 if no port specified
    if (ip_hdr.daddr == 0)
        throw runtime_error("You must specify destination ip (--dst-ip)");
    if (question.qdomain.data().length() == 1)
        throw runtime_error("You must specify domain in question (--qdomain)");
    if (question.qtype == 0)
        question.qtype = 1;
    if (question.qclass == 0)
        question.qclass = 1;

    // Set L3/L4
    _sin.sin_port = udp_hdr.source;
    _sin.sin_addr.s_addr = ip_hdr.saddr;
        
    _din.sin_port = udp_hdr.dest;
    _din.sin_addr.s_addr = ip_hdr.daddr;
    
    // Create output to send
    string output;
    string dns_dgram = data();

    output += string((char*)&ip_hdr, sizeof(ip_hdr));
    output += string((char*)&udp_hdr, sizeof(udp_hdr));
    output += dns_dgram;
    
    // Adjust lenghts
    udp_hdr.len = htons(sizeof(udp_hdr) + dns_dgram.length());
    ip_hdr.tot_len = htons(sizeof(ip_hdr) + sizeof(udp_hdr) + dns_dgram.length());
 
    if (connect(_socket, (struct sockaddr*)&_din, sizeof(_din)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": connect error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }

    if (sendto(_socket, output.data(), output.length(), 0, (struct sockaddr *)&_sin, sizeof(_sin)) < 0) {
        stringstream ss;
        ss << __func__;
        ss << ": sendto() error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }
}
