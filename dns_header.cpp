
#include "dns_header.hpp"

#include <dns_packet.hpp>

#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>

using namespace std;

DnsHeader::DnsHeader()
{
    txid = 0;
    memset(&_flags, 0x0, sizeof(DnsHeaderFlags));
    _flags.rd = 1;
    memset(nrecord, 0x0, sizeof(uint32_t) * 4);
}

DnsHeader::DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth)
{
    this->txid = txid;
    _flags.rd = 1;
    memset(&_flags, 0x0, sizeof(DnsHeaderFlags));
    nrecord[DnsPacket::R_QUESTION] = nquest;
    nrecord[DnsPacket::R_ANSWER] = nans;
    nrecord[DnsPacket::R_ADDITIONAL] = nadd;
    nrecord[DnsPacket::R_AUTHORITIES] = nauth;
}

string DnsHeader::data() const
{
    string out = "";

    uint16_t id = htons(txid);
    uint16_t temp;

    out += string((char*)&id, 2);
    //temp = *(uint16_t*)&flags;
    memcpy(&temp, &_flags, 2);
    out += string((char*)&temp, 2);

    for (int i = 0; i < 4; i++) {
        temp = htons(nrecord[i]);
        out += string((char*)&temp, 2);
    }

    return out;
}

bool DnsHeader::isQuestion() const
{
    return _flags.qr == 0;
}

bool DnsHeader::isRecursive() const
{
    return _flags.rd == 1;
}

void DnsHeader::isQuestion(bool isQuestion)
{
    _flags.qr = (isQuestion != true);
}

void DnsHeader::isRecursive(bool isRecursive)
{
    _flags.rd = (isRecursive == true);
}
