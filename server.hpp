
#ifndef __SERVER_HPP__
#define __SERVER_HPP__

#include <dns_header.hpp>
#include <dns_question.hpp>
#include <rr.hpp>
#include <dinestypes.hpp>

class Server {
    DnsHeader _hdr;
    DnsQuestion _question;
    ResourceRecord _rr;
    Dines::LogFunc _log;
    std::string _data() const;
public:
    Server(const ResourceRecord& rr, Dines::LogFunc log = NULL);
    void launch();
};

#endif
