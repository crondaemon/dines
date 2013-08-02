
#include "dns_header.hpp"

#include <dns_packet.hpp>

#include <cstring>
#include <stdexcept>
#include <sstream>
#include <arpa/inet.h>

using namespace std;

DnsHeader::DnsHeader()
{
    _txid = 0;
    memset(&_flags, 0x0, sizeof(DnsHeaderFlags));
    memset(_nRecord, 0x0, sizeof(uint32_t) * 4);

    _flags.rd = 1;
}

DnsHeader::DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth)
{
    _txid = txid;
    _flags.rd = 1;
    memset(&_flags, 0x0, sizeof(DnsHeaderFlags));
    _nRecord[DnsPacket::R_QUESTION] = nquest;
    _nRecord[DnsPacket::R_ANSWER] = nans;
    _nRecord[DnsPacket::R_ADDITIONAL] = nadd;
    _nRecord[DnsPacket::R_AUTHORITIES] = nauth;
}

string DnsHeader::data() const
{
    string out = "";

    uint16_t id = htons(_txid);
    uint16_t temp;

    out += string((char*)&id, 2);
    //temp = *(uint16_t*)&flags;
    memcpy(&temp, &_flags, 2);
    out += string((char*)&temp, 2);

    for (int i = 0; i < 4; i++) {
        temp = htons(_nRecord[i]);
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

void DnsHeader::nRecord(unsigned section, uint32_t value)
{
    _checkSection(section);
    _nRecord[section] = value;
}

uint32_t DnsHeader::nRecord(unsigned section) const
{
    _checkSection(section);
    return _nRecord[section];
}

uint16_t DnsHeader::txid() const
{
    return ntohs(_txid);
}

void DnsHeader::txid(uint16_t txid)
{
    _txid = htons(txid);
}

void DnsHeader::nRecordAdd(unsigned section, unsigned n)
{
    _checkSection(section);
    _nRecord[section] += n;
}

void DnsHeader::_checkSection(unsigned section) const
{
    if (section > 3) {
        stringstream ss;
        ss << "Invalid section: " << section;
        throw logic_error(ss.str());
    }
}
