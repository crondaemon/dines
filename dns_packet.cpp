
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

extern ostream* theLog;

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

    for (vector<ResourceRecord>::const_iterator itr = answers.begin(); 
            itr != answers.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = authoritative.begin(); 
            itr != authoritative.end(); ++itr)
        out += itr->data();

    for (vector<ResourceRecord>::const_iterator itr = additionals.begin(); 
            itr != additionals.end(); ++itr)
        out += itr->data();
    
    return out;
}

void DnsPacket::send()
{
    // Sanity checks   
    if (ip_hdr.saddr == 0)
        ; // XXX
    if (ip_hdr.daddr == 0)
        throw runtime_error("You must specify destination ip (--dst-ip)");

    if (udp_hdr.source == 0)
        udp_hdr.source = rand();
    if (udp_hdr.dest == 0)
        udp_hdr.dest = htons(53); // put 53 if no port specified

    if (dns_hdr.txid == 0)
        dns_hdr.txid = rand() % 0xFFFF;
    if (question.qdomain.size() == 1)
        throw runtime_error("You must specify DNS question (--question)");
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

    stringstream ss;

    if (sendto(_socket, output.data(), output.length(), 0, (struct sockaddr *)&_sin, sizeof(_sin)) < 0) {
        if (errno == 22) {
            cout << "Invalid parameter (probably fuzzer is shaking it).\n";
        } else {
            ss << "sendto() error: ";
            ss << strerror(errno);
            throw runtime_error(ss.str());
        }
    }
}

std::string convertDomain(const std::string& s)
{
    string out = "";
    vector<string> frags = tokenize(s, ".");
    
    for (vector<string>::const_iterator itr = frags.begin(); itr != frags.end(); ++itr) {
        // Add the len
        out.append(1, itr->length());
        // Add the frag
        out.append(*itr);
    }
    out.append(1, 0);
    
    return out;
}


