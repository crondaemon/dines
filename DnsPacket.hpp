
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>

#include "DnsHeader.hpp"

class DnsPacket {
    DnsHeader hdr;
    //DnsQuestion q;
    //vector<DnsAnswer> answers;
    //vector<DnsAdditional> additionals;
    //vector<DnsAuthoritative> autoritative;
public:
    DnsPacket();
};

#endif
