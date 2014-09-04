
#ifndef __SERVER_HPP__
#define __SERVER_HPP__

#include <dns_packet.hpp>
#include <utils.hpp>

class Server {
    DnsPacket _packet;
    uint16_t _port;
    Dines::LogFunc _log;
    std::string _data() const;
public:
    Server(const DnsPacket& packet, uint16_t port, Dines::LogFunc log = NULL);
    void logger(Dines::LogFunc l);
    void launch();
};

#endif
