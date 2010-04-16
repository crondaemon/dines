
#include <iostream>
#include <string>

#include "DnsPacket.hpp"

using namespace std;

int main(int argc, char* argv[])
{
    DnsDomain d = DnsDomain("www.ciao");

    DnsPacket p;
    
    p.dns_hdr.txid = 0x0102;
    p.dns_hdr.RecordSet(DnsHeader::R_QUESTION, 1);
    p.dns_hdr.flags.rd = 1;
    
    p.question = DnsQuestion(DnsDomain("www.pippo.com"), 1, 1);
    
    p.send();
}

