
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

    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
    ip_hdr.tos = 16;
    ip_hdr.tot_len = sizeof(struct iphdr);
    ip_hdr.id = htons(53);
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = 6;
    ip_hdr.check = 0;
    ip_hdr.daddr = inet_addr("1.2.3.4");
    ip_hdr.saddr = inet_addr("2.3.4.5");
    
    udp_hdr.source = 10;
    udp_hdr.dest = 53;
    udp_hdr.len = 100;
    udp_hdr.check = 0x1234;
}

string DnsPacket::data() const
{
    string out = "";
    
    out += dns_hdr.data();
    out += q.data();
    
    return out;
}

void DnsPacket::send() const
{
    string s;
    
    s += string((char*)&ip_hdr, sizeof(ip_hdr));
    s += string((char*)&udp_hdr, sizeof(udp_hdr));
    s += data();
    
    if (sendto(_socket, s.data(), s.length(), 0, (struct sockaddr *)&_sin, sizeof(_sin) < 0)) {
        stringstream ss;
        ss << __func__;
        ss << ": sendto() error: ";
        ss << strerror(errno);
        throw runtime_error(ss.str());
    }
}
