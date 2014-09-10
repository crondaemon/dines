
#ifndef __SERVER_HPP__
#define __SERVER_HPP__

#include <dns_packet.hpp>
#include <utils.hpp>

class Server {
    DnsPacket _incoming;
    DnsPacket _outgoing;
    uint64_t _packets;
    uint16_t _port;
    Dines::LogFunc _log;
    bool _autoanswer;
public:
    Server(const DnsPacket* packet, uint16_t port = 53, bool autoanswer = true);
    void port(uint16_t p);
    void autoanswer(bool a);
    void logger(Dines::LogFunc l);
    void launch();
};

#endif
