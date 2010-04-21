
#include <iostream>
#include <ostream>
#include <string>
#include <getopt.h>

#include "dns_packet.hpp"
#include "fuzzer.hpp"
#include "tokenizer.hpp"
#include "rr.hpp"

using namespace std;

#define VERSION 0.1

struct option opts[] = {
    {"src-ip", 1, NULL, 0},
    {"dst-ip", 1, NULL, 1},
    {"sport", 1, NULL, 2},
    {"dport", 1, NULL, 3},
    {"trid", 1, NULL, 4},
    {"num-questions", 1, NULL, 5},
    {"question", 1, NULL, 6},
    {"num-ans", 1, NULL, 7},
    {"answer", 1, NULL, 8},
    {"num-auth", 1, NULL, 9},
    {"auth", 1, NULL, 10},
    {"num-add", 1, NULL, 11},
    {"additional", 1, NULL, 12},
    {"num", 1, NULL, 30}, // <<-- appeso in fondo per lasciare spazio
    {"delay", 1, NULL, 31},
    {"debug", 0, NULL, 32},
    {NULL, 0, NULL, 0}
};

Fuzzer fuzzer;
ostream* theLog;

void usage(string s)
{
    cout << "Fields with (F) can be fuzzed. (Example --trid F)\n";
    cout << "Fields with (R) are repeatable. (Example --answer)\n";
    cout << "Fields with (A) are calculated automatically.\n";
    cout << "\n";
    cout << "Usage: " << s << " <params>\n\n";
    cout << "Params:\n";
    cout << "\n[IP]\n";
    cout << "--src-ip <ip>: Source IP\n";
    cout << "--dst-ip <ip>: Destination IP\n";
    cout << "\n[UDP]\n";
    cout << "--sport <port>: source port\n";
    cout << "--dport <port>: destination port\n";
    cout << "\n[DNS]\n";
    cout << "--trid <id>: transaction id (F)\n";
    cout << "--num-questions <n>: number of questions (A)\n";
    cout << "--question <domain>,<type>,<class>: question domain\n";
    cout << "--num-ans <n>: number of answers (A)\n";
    cout << "--answer(R) <domain>,<type>,<class>,<ttl>,<data>: a DNS answer\n";
    cout << "--num-auth <n>: number of authoritative records (A)\n";
    cout << "--auth(R) <domain>,<type>,<class>,<ttl>,<data>: a DNS authoritative record\n";
    cout << "--num-add <n>: number of additional records (A)\n";
    cout << "--additional(R) <domain>,<type>,<class>,<ttl>,<data>: a DNS additional record\n";  
    cout << "\n[MISC]\n";
    cout << "--num <n>: number of packets (0 means infinite)\n";
    cout << "--delay <usec>: delay between packets\n";
    cout << "--debug: activate debug\n";
    cout << "--help: this help\n";
    cout << "\n";
}

int main(int argc, char* argv[])
{
    int c = 0;
    string qtype = "";
    string qclass = "";
    unsigned num = 0;
    unsigned delay = 0;

    theLog = new ostream(NULL);

    cout << "\nDines " << VERSION << " - The definitive DNS packet forger.\n\n";

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }
    
    if (getuid() != 0) {
        cout << "You need to be root." << endl;
        return 1;
    }

    // Scan cmd line to dig for debug and activate it immediately
    for (int i = 0; i < argc; i++) {
        if (string(argv[i]) == "--debug") {
            cout << "Activating DEBUG\n";
            theLog = new ostream(cout.rdbuf());
        }
        if (string(argv[i]) == "--help") {
            usage(argv[0]);
            return 1;
        }
    }

    // Create a packet
    DnsPacket p;
    vector<string> tokens;
    ResourceRecord rr;
    
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
                p.dns_hdr.nrecord[DnsHeader::R_QUESTION] = atoi(optarg);
            break;
            
            case 6:
                tokens.clear();
                tokens = tokenize(optarg, ",");
                
                if (tokens.at(1).at(0) == 'F')
                    fuzzer.addAddress(&p.question.qtype, 2);
                else
                    qtype = tokens.at(1);

                if (tokens.at(2).at(0) == 'F')
                    fuzzer.addAddress(&p.question.qclass, 2);
                else
                    qclass = tokens.at(2);
                    
                p.dns_hdr.nrecord[DnsHeader::R_QUESTION] = 1;
                p.question = DnsQuestion(tokens.at(0), qtype, qclass);
            break;
            
            case 7:
                p.dns_hdr.nrecord[DnsHeader::R_ANSWER] = atoi(optarg);
            break;
            
            case 8:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2), 
                    tokens.at(3), tokens.at(4));

                p.dns_hdr.flags.qr = 1;
                p.answers.push_back(rr);
                p.dns_hdr.nrecord[DnsHeader::R_ANSWER]++;
            break;

            case 9:
                p.dns_hdr.nrecord[DnsHeader::R_AUTHORITATIVE] = atoi(optarg);
            break;
            
            case 10:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2), 
                    tokens.at(3), tokens.at(4));

                p.dns_hdr.flags.qr = 1;
                p.authoritative.push_back(rr);
                p.dns_hdr.nrecord[DnsHeader::R_AUTHORITATIVE]++;
            break;

            case 11:
                p.dns_hdr.nrecord[DnsHeader::R_ADDITIONAL] = atoi(optarg);
            break;
            
            case 12:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2), 
                    tokens.at(3), tokens.at(4));

                p.additionals.push_back(rr);
                p.dns_hdr.nrecord[DnsHeader::R_ADDITIONAL]++;
            break;
            
            case 30:
                num = atoi(optarg);
            break;
            
            case 31:
                delay = atoi(optarg);
            break;
            
            case 32:
                //cout << "Activating debug\n";
                //theLog = new ostream(cout.rdbuf());
            break;
            
            default:
                cout << "Unknown option.\n";
                return 1;
        }
    }


    // Other options
    p.dns_hdr.flags.rd = 1;

    if (num == 0)
        num = 0xFFFFFF;

    if (delay == 0)
        delay = 1000000;

    cout << "Sending";
    // Send datagram    
    while(num-- > 0) {
        fuzzer.goFuzz();

        try {
            p.sendNet();
        }
        catch(exception& e) {
            cout << "\n\nError: " << e.what() << "\n";
            return 1;
        }

        cout << "."; cout.flush();

        if (num > 0) usleep(delay);
    }
    cout << endl;
}

