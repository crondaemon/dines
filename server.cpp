
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

using namespace std;

Server::Server(const ResourceRecord& rr, Dines::LogFunc log) :
        _rr(rr), _log(log)
{
    if (_log)
        _log("Creating server");
}

void Server::launch()
{
    if (_log)
        _log("Serving record: " + _rr.to_string());

    int servSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (servSock == -1)
        throw runtime_error(string(__func__) + ": can't create socket");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(53);

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

        _hdr.parse(buf);
        _question.parse(buf + 12);

        _hdr.isQuestion(false);
        _hdr.nRecord(Dines::R_ANSWER, 1);

        if (_log)
            _log("Query from: " + Dines::ip32ToString(peer.sin_addr.s_addr));

        if (sendto(servSock, _data().data(), _data().size(), 0, (struct sockaddr*)&peer,
                sockaddr_len) == -1) {
            throw runtime_error(string(__func__) + "::sendto() error: " + string(strerror(errno)));
        }
    }
}

string Server::_data() const
{
    return _hdr.data() + _question.data() + _rr.data();
}
