
#include <dns_header.hpp>

#include <dns_packet.hpp>
#include <debug.hpp>

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
    _nRecord[Dines::R_QUESTION] = htons(nquest);
    _nRecord[Dines::R_ANSWER] = htons(nans);
    _nRecord[Dines::R_ADDITIONAL] = htons(nadd);
    _nRecord[Dines::R_AUTHORITIES] = htons(nauth);

    _fuzzFlags = false;
    _fuzzTxid = false;
    _fuzzNRecord[0] = false;
    _fuzzNRecord[1] = false;
    _fuzzNRecord[2] = false;
    _fuzzNRecord[3] = false;

    srand(time(NULL));

    if (_txid == 0)
        _txid = rand();
}

DnsHeader::DnsHeader(const DnsHeader& h)
{
    *this = h;
}

DnsHeader& DnsHeader::operator=(const DnsHeader& h)
{
    _txid = h._txid;
    _flags = h._flags;
    memcpy(&_nRecord, h._nRecord, sizeof(_nRecord));
    _fuzzFlags = h._fuzzFlags;
    _fuzzTxid = h._fuzzTxid;
    memcpy(&_fuzzNRecord, h._fuzzNRecord, sizeof(_fuzzNRecord));
    return *this;
}

string DnsHeader::data() const
{
    string out = "";

    out += string((char*)&_txid, 2);
    out += string((char*)&_flags, 2);

    for (int i = 0; i < 4; i++) {
        out += string((char*)&_nRecord[i], 2);
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
    _nRecord[section] = htons(value);
}

uint16_t DnsHeader::nRecord(unsigned section) const
{
    _checkSection(section);
    return ntohs(_nRecord[section]);
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
    _nRecord[section] = htons(ntohs(_nRecord[section]) + n);
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
    unsigned seed = time(NULL);
    if (_fuzzTxid == true) {
        _txid = rand_r(&seed);
    }

    if (_fuzzFlags == true) {
        uint16_t v = rand();
        DnsHeaderFlags* f = (DnsHeaderFlags*)(u_char*)(&v);
        _flags = *f;
    }

    if (_fuzzNRecord[Dines::R_QUESTION] == true) {
        _nRecord[Dines::R_QUESTION] = rand();
    }

    if (_fuzzNRecord[Dines::R_ANSWER] == true) {
        _nRecord[Dines::R_ANSWER] = rand();
    }

    if (_fuzzNRecord[Dines::R_ADDITIONAL] == true) {
        _nRecord[Dines::R_ADDITIONAL] = rand();
    }

    if (_fuzzNRecord[Dines::R_AUTHORITIES] == true) {
        _nRecord[Dines::R_AUTHORITIES] = rand();
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

void DnsHeader::parse(char* buf)
{
    memcpy(&_txid, buf, 2);
    memcpy(&_flags, buf + 2, 2);
    memcpy(&_nRecord, buf + 4, 8);
}

bool DnsHeader::rd() const
{
    return _flags.rd == 1;
}

bool DnsHeader::ra() const
{
    return _flags.ra == 1;
}

void DnsHeader::rd(bool rec_des)
{
    _flags.rd = (rec_des == true ? 1 : 0);
}

void DnsHeader::ra(bool rec_avail)
{
    _flags.ra = (rec_avail == true ? 1 : 0);
}
