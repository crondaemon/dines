
#include "dns_header.hpp"

#include <dns_packet.hpp>

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

DnsHeader::DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth)
{
    _txid = htons(txid);
    memset(&_flags, 0x0, sizeof(DnsHeaderFlags));
    _flags.rd = 1;
    _nRecord[DnsPacket::R_QUESTION] = nquest;
    _nRecord[DnsPacket::R_ANSWER] = nans;
    _nRecord[DnsPacket::R_ADDITIONAL] = nadd;
    _nRecord[DnsPacket::R_AUTHORITIES] = nauth;

    _fuzzFlags = false;
    _fuzzTxid = false;
    _fuzzNRecord[0] = false;
    _fuzzNRecord[1] = false;
    _fuzzNRecord[2] = false;
    _fuzzNRecord[3] = false;

    srand(time(NULL));
}

string DnsHeader::data() const
{
    string out = "";

    uint16_t id = htons(_txid);
    uint16_t temp;

    out += string((char*)&id, 2);
    out += string((char*)&_flags, 2);

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

void DnsHeader::nRecord(unsigned section, uint16_t value)
{
    _checkSection(section);
    _nRecord[section] = value;
}

uint16_t DnsHeader::nRecord(unsigned section) const
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
        char s[10];
        snprintf(s, 10, "%d", section);
        throw logic_error("Invalid section: " + string(s));
    }
}

void DnsHeader::fuzz()
{
    if (_fuzzTxid == true) {
        _txid = rand() % 65535;
    }

    if (_fuzzFlags == true) {
        uint16_t v = rand() % 65535;
        _flags = *(DnsHeaderFlags*)(&v);
    }

    if (_fuzzNRecord[DnsPacket::R_QUESTION] == true) {
        _nRecord[DnsPacket::R_QUESTION] = rand() % 65535;
    }

    if (_fuzzNRecord[DnsPacket::R_ANSWER] == true) {
        _nRecord[DnsPacket::R_ANSWER] = rand() % 65535;
    }

    if (_fuzzNRecord[DnsPacket::R_ADDITIONAL] == true) {
        _nRecord[DnsPacket::R_ADDITIONAL] = rand() % 65535;
    }

    if (_fuzzNRecord[DnsPacket::R_AUTHORITIES] == true) {
        _nRecord[DnsPacket::R_AUTHORITIES] = rand() % 65535;
    }
}

void DnsHeader::fuzzFlags()
{
    _fuzzFlags = true;
}

void DnsHeader::fuzzTxid()
{
    _fuzzTxid = true;
}

void DnsHeader::fuzzNRecord(unsigned section)
{
    _checkSection(section);
    _fuzzNRecord[section] = true;
}

DnsHeaderFlags DnsHeader::flags() const
{
    return _flags;
}

bool operator==(const DnsHeaderFlags& f1, const DnsHeaderFlags& f2)
{
    return
        (f1.qr == f2.qr) &&
        (f1.opcode == f2.opcode) &&
        (f1.aa == f2.aa) &&
        (f1.tc == f2.tc) &&
        (f1.rd == f2.rd) &&
        (f1.ra == f2.ra) &&
        (f1.z == f2.z) &&
        (f1.auth == f2.auth) &&
        (f1.cd == f2.cd) &&
        (f1.rcode == f2.rcode);
}

bool operator!=(const DnsHeaderFlags& f1, const DnsHeaderFlags& f2)
{
    return !(f1 == f2);
}
