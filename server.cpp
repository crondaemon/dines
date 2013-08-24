
#include <server.hpp>

#include <debug.hpp>
#include <convert.hpp>
#include <iostream>
#include <string>
#include <stdexcept>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <convert.hpp>

using namespace std;

Server::Server(const DnsPacket& p, uint16_t port, Dines::LogFunc log) :
        _p(p), _port(port), _log(log)
{
    if (_log)
        _log("Creating server");

    if (_p.nRecord(Dines::R_QUESTION) > 0) {
        throw runtime_error("Can't specify question when running in server mode");
    }
}

void Server::setLogger(Dines::LogFunc l)
{
    _log = l;
    _log("Activating logger");
}

void Server::launch()
{
    char port[7];
    snprintf(port, 7, "%u", _port);

    if (_log)
        _log("Serving record: " + _p.to_string(true) + " on port " + string(port));

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

    while(1) {
        datalen = recvfrom(servSock, buf, buflen, 0, (struct sockaddr*)&peer, &sockaddr_len);
        if (datalen == -1) {
            throw runtime_error(string(__func__) + ": can't recvfrom()");
        }

        DnsHeader qhdr;
        qhdr.parse(buf);

        DnsHeader& h = _p.dnsHdr();

        h.txid(qhdr.txid());
        if (qhdr.rd() == true) {
            h.ra(true);
        }

        DnsQuestion q;
        q.parse(buf + 12);

        _p.addQuestion(q);
        _p.isQuestion(false);

        if (_log)
            _log("Query from: " + Dines::ip32ToString(peer.sin_addr.s_addr) +
                " txid: " + Dines::convertInt<uint16_t>(h.txid()));

        if (sendto(servSock, _data().data(), _data().size(), 0, (struct sockaddr*)&peer,
                sockaddr_len) == -1) {
            throw runtime_error(string(__func__) + "::sendto() error: " + string(strerror(errno)));
        }

        _p.fuzz();
    }
}

string Server::_data() const
{
    return _p.data();
}
