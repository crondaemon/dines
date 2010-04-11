
#include <iostream>

#include "DnsPacket.hpp"

int main(int argc, char* argv[])
{
    DnsPacket p;
    
    p.hdr.txid(0x0102);
    p.hdr.RecordSet(R_QUESTION, 1);
}

