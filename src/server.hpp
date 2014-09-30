
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
    uint32_t _upstream;
    void _directAnswer(int sock, struct sockaddr_in peer);
    void _recursion(int sock, struct sockaddr_in peer);
public:
    Server(const DnsPacket& packet, uint16_t port = 53, bool autoanswer = true);
    void port(uint16_t p);
    void autoanswer(bool a);
    void logger(Dines::LogFunc l);
    void launch();
    void packets(uint64_t p);
    bool invalid() const;
    std::string invalidMsg() const;
    void upstream(uint32_t ups);
    std::string upstream() const;
};

#endif
