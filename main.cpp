
#include <iostream>
#include <string>
#include <getopt.h>

#include "DnsPacket.hpp"

using namespace std;

struct option opts[] = {
    {"src-ip", 1, NULL, 0},
    {"dst-ip", 1, NULL, 1},
    {"trid", 1, NULL, 2},
    {"qtype", 1, NULL, 3},
    {"qdomain", 1, NULL, 4},
    { NULL, 0, NULL, 0}
};

void usage()
{
}

int main(int argc, char* argv[])
{
    DnsPacket p;
    
    int c;

    while((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch(c) {
            case 0:
                p.ip_hdr.saddr = inet_addr(optarg);
                break;
            case 1:
                p.ip_hdr.daddr = inet_addr(optarg);
                break;
            case 2:
                p.dns_hdr.txid = htons(atoi(optarg));
                break;
            case 3:
                p.dns_hdr.RecordSet(DnsHeader::RecordType(atoi(optarg)), 1);
                break;
            case 4:
                p.question = DnsQuestion(DnsDomain(optarg), 1, 1);
                break;
            default:
                printf("ERRORE\n");
        }
    }

    // Other options
    p.dns_hdr.flags.rd = 1;

    // Send datagram    
    p.send();
}

