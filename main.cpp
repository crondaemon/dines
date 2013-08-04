
#include <iostream>
#include <ostream>
#include <string>
#include <stdexcept>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include <dns_packet.hpp>
#include <tokenizer.hpp>
#include <rr.hpp>
#include <config.h>

using namespace std;

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
    // some space here for new params
    {"num", 1, NULL, 30},
    {"delay", 1, NULL, 31},
    {"debug", 0, NULL, 32},
    {"verbose", 0, NULL, 33},
    {NULL, 0, NULL, 0}
};

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
    cout << "--src-ip <ip>: Source IP (default: local address)\n";
    cout << "--dst-ip <ip>: Destination IP\n";
    cout << "\n[UDP]\n";
    cout << "--sport <port>: source port\n";
    cout << "--dport <port>: destination port (default: 53)\n";
    cout << "\n[DNS]\n";
    cout << "--trid <id>: transaction id (F)\n";
    cout << "--num-questions <n>: number of questions (A)\n";
    cout << "--question <domain>,<type(F)>,<class>: question domain\n";
    cout << "\n";
    cout << "--num-ans <n>: number of answers (A)\n";
    cout << "--answer(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS answer\n";
    cout << "\n";
    cout << "--num-auth <n>: number of authoritative records (A)\n";
    cout << "--auth(R) <domain>,<type>,<class(F)>,<ttl(F)>,<data>: a DNS authoritative record\n";
    cout << "\n";
    cout << "--num-add <n>: number of additional records (A)\n";
    cout << "--additional(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS additional record\n";
    cout << "\n[MISC]\n";
    cout << "--num <n>: number of packets (0 means infinite)\n";
    cout << "--delay <usec>: delay between packets\n";
    cout << "--debug: activate debug\n";
    cout << "--verbose: be verbose\n";
    cout << "--help: this help\n";
    cout << "\n";
}

int main(int argc, char* argv[])
{
    int c = 0;
    string qtype = "";
    string qclass = "";
    unsigned num = 0;
    unsigned delay = 1000000;
    bool verbose = false;
    uint16_t forged_nrecords[4];

    memset(&forged_nrecords, 0x0, sizeof(forged_nrecords));

    theLog = new ostream(NULL);

    cout << "\nDines " << PACKAGE_VERSION << " - The definitive DNS packet forger.\n\n";

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }

    // Scan cmd line to dig for options and activate them immediately
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

    if (getuid() != 0) {
        cout << "You need to be root." << endl;
        return 1;
    }

    // Create a packet
    DnsPacket p;
    vector<string> tokens;
    ResourceRecord rr;

    while((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch(c) {
            case 0:
                if (optarg[0] == 'F') {
                    throw runtime_error("Fuzzer unsupported");
                    //p.fuzzer.addAddress(&p.ip_hdr.saddr, 4);
                } else {
                    p.ipFrom(optarg);
                }
                break;

            case 1:
                p.ipTo(optarg);
                break;

            case 2:
                p.sport(optarg);
                break;

            case 3:
                p.dport(optarg);
                break;

            case 4:
                if (optarg[0] == 'F') {
                    throw runtime_error("Fuzzer unsupported");
                    //p.fuzzer.addAddress(&p.dnsHdr.txid, 2);
                } else {
                    p.txid(optarg);
                }
                break;

            case 5:
                forged_nrecords[DnsPacket::R_QUESTION] = atoi(optarg);
                break;

            case 6:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                if (tokens.size() != 3) {
                    cout << "Syntax: --question <domain>,<type>,<class>\n";
                    return 1;
                }

                p.addQuestion(tokens.at(0), tokens.at(1), tokens.at(2));
                break;

            case 7:
                forged_nrecords[DnsPacket::R_ANSWER] = atoi(optarg);
                break;

            case 8:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                p.isQuestion(false);
                p.addRR(DnsPacket::R_ANSWER, tokens.at(0), tokens.at(1), tokens.at(2),
                        tokens.at(3), tokens.at(4));
                break;

            case 9:
                forged_nrecords[DnsPacket::R_AUTHORITIES] = atoi(optarg);
                break;

            case 10:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                p.isQuestion(false);
                p.addRR(DnsPacket::R_AUTHORITIES, tokens.at(0), tokens.at(1), tokens.at(2),
                    tokens.at(3), tokens.at(4));
                break;

            case 11:
                forged_nrecords[DnsPacket::R_ADDITIONAL] = atoi(optarg);
                break;

            case 12:
                tokens.clear();
                tokens = tokenize(optarg, ",");

                p.addRR(DnsPacket::R_ADDITIONAL, tokens.at(0), tokens.at(1), tokens.at(2),
                    tokens.at(3), tokens.at(4));
                break;

            case 30:
                num = atoi(optarg);
                *theLog << "About to send " << num << " packets." << endl;
                break;

            case 31:
                delay = atoi(optarg);
                *theLog << "Inter packet gap set to " << delay << endl;
                break;

            case 32:
                //cout << "Activating debug\n";
                //theLog = new ostream(cout.rdbuf());
                break;

            case 33:
                cout << "Verbose: ON" << endl;
                verbose = true;
                break;
            default:
                cout << "Unknown option.\n";
                return 1;
        }
    }

    for (unsigned i = 0; i < 4; i++) {
        if (forged_nrecords[i] != 0) {
            p.nRecord(DnsPacket::RecordSection(i), forged_nrecords[i]);
        }
    }

    if (num == 0)
        num = 0xFFFFFF;

    cout << "Sending " << num << " datagrams" << endl;
    // Send datagram
    while (num-- > 0) {
        //p.fuzzer.goFuzz();
        try {
            p.sendNet();
        } catch(exception& e) {
            cout << "\n\nError: " << e.what() << "\n";
            return 1;
        }

        if (verbose) {
            cout << p.to_string() << endl;
        }

        if (num > 0)
            usleep(delay);
    }
    cout << endl;
}
