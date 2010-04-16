
#include <iostream>
#include <ostream>
#include <string>
#include <getopt.h>

#include "dns_packet.hpp"
#include "fuzzer.hpp"

using namespace std;

#define VERSION 0.1

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
    {"debug", 0, NULL, 32},
    {NULL, 0, NULL, 0}
};

Fuzzer fuzzer;
ostream* theLog;

void usage(string s)
{
    cout << "Fields with (F) can be fuzzed. (Example --trid F)\n\n";
    cout << "Usage: " << s << " <params>\n\n";
    cout << "Params:\n";
    cout << "\n[IP]\n";
    cout << "--src-ip: Source IP\n";
    cout << "--dst-ip: Destination IP\n";
    cout << "\n[UDP]\n";
    cout << "--sport: source port\n";
    cout << "--dport: destination port\n";
    cout << "\n[DNS]\n";
    cout << "--trid: transaction id (F)\n";
    cout << "--qdomain: question domain\n";
    cout << "--qtype: question type (F)\n";
    cout << "--qclass: question class (F)\n";
    cout << "\n[MISC]\n";
    cout << "--num: number of packets (0 means infinite)\n";
    cout << "--delay: delay between packets (in usec)\n";
    cout << "--debug: activate debug\n";
    cout << "\n";
}

int main(int argc, char* argv[])
{
    int c = 0;
    int type = 0;
    int cl = 0;
    unsigned num = 0;
    unsigned delay = 0;

    theLog = new ostream(NULL);

    cout << "\nDines " << VERSION << " - The definitive DNS packet forger.\n\n";

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
                if (optarg[0] == 'F')
                    fuzzer.addAddress(&p.ip_hdr.saddr, 4);
                else
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
                if (optarg[0] == 'F')
                    fuzzer.addAddress(&p.dns_hdr.txid, 2);
                else
                    p.dns_hdr.txid = htons(atoi(optarg));
                break;
            case 5:
                domain = DnsDomain(optarg);
                break;
            case 6:
                if (optarg[0] == 'F')
                    fuzzer.addAddress(&p.question.qtype, 2);
                else
                    type = atoi(optarg);
                break;
            case 7:
                if (optarg[0] == 'F')
                    fuzzer.addAddress(&p.question.qclass, 2);
                else
                    cl = atoi(optarg);
                break;
            case 30:
                num = atoi(optarg);
                break;
            case 31:
                delay = atoi(optarg);
                break;
            case 32:
                cout << "Activating debug\n";
                theLog = new ostream(cout.rdbuf());
                break;
            default:
                cout << "Unknown option.\n";
                return 1;
        }
    }


    // Other options
    p.dns_hdr.RecordSet(DnsHeader::R_QUESTION, 1);
    p.question = DnsQuestion(domain, type, cl);
    p.dns_hdr.flags.rd = 1;

    if (num == 0)
        num = 0xFFFFFF;

    if (delay == 0)
        delay = 1000000;

    cout << "Sending";
    // Send datagram    
    while(num-- > 0) {
        fuzzer.goFuzz();

        //*theLog << p.ip_hdr.saddr << "->" << p.ip_hdr.daddr << endl;
            
        try {
            p.send();
        }
        catch(exception& e) {
            cout << "\n\nError: " << e.what() << "\n";
            return 1;
        }

        cout << "."; cout.flush();

        usleep(delay);
    }
    cout << endl;
}

