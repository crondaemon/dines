
#include "DnsHeader.hpp"

#include <cstring>
#include <stdexcept>

using namespace std;

DnsHeader::DnsHeader()
{
    _txid = 0;
    memset(&_txid, 0x0, sizeof(uint32_t) * 4);
}

DnsHeader::DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth)
{
    _txid = txid;
    _nrecord[R_QUESTION] = nquest;
    _nrecord[R_ANSWER] = nans;
    _nrecord[R_ADDITIONAL] = nadd;
    _nrecord[R_AUTHORITATIVE] = nauth;
}

void DnsHeader::RecordSet(const RecordType rt, const uint32_t value)
{
    if (rt >=4)
        throw logic_error("Invalid RecordType " + rt);

    _nrecord[rt] = value;
}

uint32_t DnsHeader::RecordGet(const RecordType rt) const 
{
    if (rt >= 4)
        throw logic_error("Invalid RecordType " + rt);
        
    return _nrecord[rt];
}

void DnsHeader::RecordAdd(const RecordType rt, const int value)
{
    if (rt >= 4)
        throw logic_error("Invalid RecordType " + rt);

    _nrecord[rt] += value;
}    

void DnsHeader::RecordInc(const RecordType rt)
{
    this->RecordAdd(rt, 1);
}    
