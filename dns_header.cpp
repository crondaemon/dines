
#include "dns_header.hpp"

#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>

using namespace std;

DnsHeader::DnsHeader()
{
    txid = 0;
    memset(&flags, 0x0, sizeof(DnsHeaderFlags));
    memset(nrecord, 0x0, sizeof(uint32_t) * 4);
}

DnsHeader::DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth)
{
    this->txid = txid;
    memset(&flags, 0x0, sizeof(DnsHeaderFlags));
    nrecord[R_QUESTION] = nquest;
    nrecord[R_ANSWER] = nans;
    nrecord[R_ADDITIONAL] = nadd;
    nrecord[R_AUTHORITATIVE] = nauth;
}

string DnsHeader::data() const
{
    string out = "";

    uint16_t id = htons(txid);
    uint16_t temp;

    out += string((char*)&id, 2);
    //temp = *(uint16_t*)&flags;
    memcpy(&temp, &flags, 2);
    out += string((char*)&temp, 2);

    for (int i = 0; i < 4; i++) {
        temp = htons(nrecord[i]);
        out += string((char*)&temp, 2);
    }

    return out;
}

bool DnsHeader::question() const
{
    return flags.qr == 0;
}
