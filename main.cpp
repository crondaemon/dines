
#include <iostream>

#include "DnsPacket.hpp"

int main(int argc, char* argv[])
{
    DnsPacket p;
    
    p.dns_hdr.txid(0x0102);
    p.dns_hdr.RecordSet(R_QUESTION, 1);
    
    p.send();
}

