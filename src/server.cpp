
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

Server::Server(const DnsPacket* packet, uint16_t port, bool autoanswer)
{
    _log = NULL;
    _port = port;
    _autoanswer = autoanswer;
    _packets = -1;
    if (packet) {
        _outgoing = *packet;
        if (_outgoing.nRecord(Dines::R_QUESTION) > 0) {
            throw runtime_error("Can't specify question when running in server mode");
        }
    }
}

void Server::logger(Dines::LogFunc l)
{
    _log = l;
    if (_log)
        _log("Activating logger");
}

void Server::autoanswer(bool a)
{
    _autoanswer = a;
}

void Server::launch()
{
    if (_autoanswer && _log)
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
        throw runtime_error("Can't bind() listening socket");

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
        _outgoing.dnsHdr().txid(_incoming.dnsHdr().txid());
//        _outgoing.question(_incoming.question());
        _outgoing.isQuestion(false);

        if (sendto(servSock, _outgoing.data().data(), _outgoing.data().size(), 0, (struct sockaddr*)&peer,
                sockaddr_len) == -1) {
            throw runtime_error(string(__func__) + "::sendto() error: " + string(strerror(errno)));
        }

        _outgoing.fuzz();
        _packets--;
    }
}
