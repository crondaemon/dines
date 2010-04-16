
#include <iostream>
#include <string>
#include <getopt.h>

#include "DnsPacket.hpp"

using namespace std;

struct option opts[] = {
    {"src-ip", 1, NULL, 0},
    {"dst-ip", 1, NULL, 1},
    {"sport", 1, NULL, 2},
    {"dport", 1, NULL, 3},
    {"trid", 1, NULL, 4},
    {"qdomain", 1, NULL, 5},
    {"qtype", 1, NULL, 6},
    {"qclass", 1, NULL, 7},
    {"num", 1, NULL, 30}, // <<-- appeso in fondo per lasciare spazio
    {"delay", 1, NULL, 31},
    { NULL, 0, NULL, 0}
};

void usage(string s)
{
    cout << "\nDines 0.1\n\n";
    cout << "Usage: " << s << " <params>\n\n";
    cout << "Params:\n\n";
    cout << "[IP]\n";
    cout << "--src-ip: Source IP\n";
    cout << "--dst-ip: Destination IP\n";
    cout << "\n[UDP]\n";
    cout << "--sport: source port\n";
    cout << "--dport: destination port\n";
    cout << "\n[DNS]\n";
    cout << "--trid: transaction id\n";
    cout << "--qdomain: question domain\n";
    cout << "--qtype: question type\n";
    cout << "--qclass: question class\n";
    cout << "\n[MISC]\n";
    cout << "--num: number of packets (0 means infinite)\n";
    cout << "--delay: delay between packets (in usec)\n";
    cout << "\n";
}

int main(int argc, char* argv[])
{
    int c;
    int type;
    int cl;
    unsigned num = 0;
    unsigned delay = 0;

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }

    // Create a packet
    DnsPacket p;
    DnsDomain domain;
    
    while((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch(c) {
            case 0:
                p.ip_hdr.saddr = inet_addr(optarg);
                break;
            case 1:
                p.ip_hdr.daddr = inet_addr(optarg);
                break;
            case 2:
                p.udp_hdr.source = htons(atoi(optarg));
                break;
            case 3:
                p.udp_hdr.dest = htons(atoi(optarg));
                break;
            case 4:
                p.dns_hdr.txid = htons(atoi(optarg));
                break;
            case 5:
                domain = DnsDomain(optarg);
                break;
            case 6:
                type = atoi(optarg);
                break;
            case 7:
                cl = atoi(optarg);
                break;
            case 30:
                num = atoi(optarg);
                break;
            case 31:
                delay = atoi(optarg);
                break;
            default:
                cout << "Unknown option.\n";
        }
    }


    // Other options
    p.dns_hdr.RecordSet(DnsHeader::R_QUESTION, 1);
    p.question = DnsQuestion(domain, type, cl);
    p.dns_hdr.flags.rd = 1;

    if (num == 0)
        num = 0xFFFFFF;

    cout << "Sending";
    // Send datagram    
    while(num > 0) {
        try {
            p.send();
        }
        catch(exception& e) {
            cout << "\n\nError: " << e.what() << "\n\n";
            return 1;
        }
        cout << ".";
        cout.flush();
        usleep(delay);
        num--;
    }
    cout << endl;
}

