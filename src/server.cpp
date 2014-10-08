
#include <server.hpp>

#include <debug.hpp>
#include <iostream>
#include <string>
#include <stdexcept>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <utils.hpp>

using namespace std;

Server::Server(const DnsPacket& packet, uint16_t port)
{
    _log = NULL;
    this->port(port);
    this->packets(-1);
    _outgoing = packet;
    _upstream = 0;
    _upstream_port = htons(port);
}

void Server::logger(Dines::LogFunc l)
{
    _log = l;
    if (_log)
        _log("Activating logger");
}

void Server::launch()
{
    if (_log)
        _log("Serving record: " + _outgoing.to_string(true) + " on port " + std::to_string(_port));

    int servSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (servSock == -1)
        throw runtime_error(string(__func__) + ": can't create socket");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(_port);

    if (bind(servSock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 )
        BASIC_EXCEPTION_THROW("bind");

    const unsigned buflen = 65535;
    char buf[buflen];

    struct sockaddr_in peer;
    unsigned sockaddr_len = sizeof(struct sockaddr_in);

    int datalen;

    while(_packets > 0) {
        datalen = recvfrom(servSock, buf, buflen, 0, (struct sockaddr*)&peer, &sockaddr_len);
        if (datalen == -1) {
            throw runtime_error(string(__func__) + ": can't recvfrom()");
        }

        _incoming.parse(buf);
        if (_log)
            _log("Incoming packet: " + _incoming.to_string(true));

        if (_incoming.dnsHdr().rd() == true) {
            _outgoing.dnsHdr().ra(true);
        }

        if (_upstream > 0 && (_incoming.question() != _outgoing.question())) {
            if (_log)
                _log("Recursion activated towards " + Dines::ip32ToString(_upstream));
            this->_recursion(servSock, peer);
        } else {
            this->_directAnswer(servSock, peer);
        }

        _packets--;
        _incoming.clear();
    }
}

void Server::_recursion(int sock, struct sockaddr_in peer)
{
    // Create a new packet
    DnsPacket upstream_packet;
    // Set the question as the incoming question
    upstream_packet.question(_incoming.question());
    // Set the server as upstream
    upstream_packet.to(_upstream);
    upstream_packet.dport(ntohs(_upstream_port));
    // Inject the packet and get the response back
    DnsPacket* return_packet = upstream_packet.sendNet();
    if (_log) {
        _log("Recursion out " + upstream_packet.to_string());
        _log("Recursion in " + return_packet->to_string());
    }
    // Force the txid in the response
    return_packet->txid(_incoming.txid());

    // Send the payload back
    if (sendto(sock, return_packet->data().data(), return_packet->data().size(), 0, (struct sockaddr*)&peer,
            sizeof(peer)) == -1) {
        BASIC_EXCEPTION_THROW("sendto");
    }
}

void Server::_directAnswer(int sock, struct sockaddr_in peer)
{
    unsigned sockaddr_len = sizeof(struct sockaddr_in);

    _outgoing.dnsHdr().txid(_incoming.dnsHdr().txid());
    _outgoing.question(_incoming.question());
    _outgoing.isQuestion(false);

    if (sendto(sock, _outgoing.data().data(), _outgoing.data().size(), 0, (struct sockaddr*)&peer,
            sockaddr_len) == -1) {
        BASIC_EXCEPTION_THROW("sendto");
    }

    _outgoing.fuzz();
    _outgoing.question().clear();
}

void Server::packets(uint64_t p)
{
    if (_log)
        _log("Setting packets to " + to_string(p));
    _packets = p;
}

void Server::port(uint16_t p)
{
    if (_log)
        _log("Setting port to " + to_string(p));
    _port = p;
}

bool Server::invalid() const
{
    if (this->invalidMsg() != "")
        return true;
    return false;
}

string Server::invalidMsg() const
{
    if ((_outgoing.nRecord(Dines::R_QUESTION) > 0 && _upstream ==0) ||
            (_outgoing.nRecord(Dines::R_QUESTION) == 0 && _upstream > 0)) {
        throw runtime_error("--question and --upstream must be specified together in server mode");
    }
    return "";
}

void Server::upstream(uint32_t ups, uint16_t port)
{
    _upstream = ups;
    _upstream_port = htons(port);
}

string Server::upstream() const
{
    return Dines::ip32ToString(_upstream);
}
