
#ifndef __DNSPACKET_HPP__
#define __DNSPACKET_HPP__

#include <vector>
#include <cstdint>

#include "DnsHeader.hpp"
#include "DnsQuestion.hpp"

class DnsPacket {
public:
    DnsHeader hdr;
    
    DnsQuestion q;
    
    //vector<DnsAnswer> answers;
    
    //vector<DnsAdditional> additionals;
    
    //vector<DnsAuthoritative> autoritative;
    
    DnsPacket() {}
};

#endif
