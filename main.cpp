
#include <iostream>
#include <ostream>
#include <string>
#include <stdexcept>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <dns_packet.hpp>
#include <tokenizer.hpp>
#include <rr.hpp>
#include <config.h>
#include <server.hpp>
#include <convert.hpp>

using namespace std;

struct option opts[] = {
    {"src-ip", 1, NULL, 0},
    {"dst-ip", 1, NULL, 1},
    {"sport", 1, NULL, 2},
    {"dport", 1, NULL, 3},
    {"txid", 1, NULL, 4},
    {"num-questions", 1, NULL, 5},
    {"question", 1, NULL, 6},
    {"num-ans", 1, NULL, 7},
    {"answer", 1, NULL, 8},
    {"num-auth", 1, NULL, 9},
    {"auth", 1, NULL, 10},
    {"num-add", 1, NULL, 11},
    {"additional", 1, NULL, 12},
    // some space here for new params
    {"no-rd", 0, NULL, 28},
    {"server", 2, NULL, 29},
    {"num", 1, NULL, 30},
    {"delay", 1, NULL, 31},
    {"verbose", 0, NULL, 32},
    {NULL, 0, NULL, 0}
};

void usage(string s)
{
    cout << "Fields with (F) can be fuzzed. (Example --txid F)\n";
    cout << "Fields with (F<n>) can be fuzzed for a specific length (Example --question F20,A,IN)\n";
    cout << "Fields with (R) are repeatable. (Example --answer)\n";
    cout << "Fields with (A) are calculated automatically.\n";
    cout << "\n";
    cout << "Usage: " << s << " <params>\n\n";
    cout << "Params:\n";
    cout << "\n[IP]\n";
    cout << "--src-ip=<ip>: Source IP (AF)\n";
    cout << "--dst-ip=<ip>: Destination IP\n";
    cout << "\n[UDP]\n";
    cout << "--sport=<port>: source port (A)\n";
    cout << "--dport=<port>: destination port (A)\n";
    cout << "\n[DNS]\n";
    cout << "--txid=<id>: transaction id (AF)\n";
    cout << "--no-rd: no recursion desired (A)\n";
    cout << "--num-questions=<n>: number of questions (AF)\n";
    cout << "--question=<domain(F<n>)>,<type(F)>,<class(F)>: question domain\n";
    cout << "\n";
    cout << "--num-ans=<n>: number of answers (AF)\n";
    cout << "--answer(R)=<domain(F<n>)>,<type(F)>,<class(F)>,<ttl(F)>,<rdata>: a DNS answer\n";
    cout << "--answer(R)=<domain(F<n>)>,<type(F)>,<class(F)>,<ttl(F)>,<rdatalen>,<rdata>: a DNS answer\n";
    cout << "\n";
    cout << "--num-auth=<n>: number of authoritative records (AF)\n";
    cout << "--auth(R)=<domain(F<n>)>,<type>,<class(F)>,<ttl(F)>,<rdata>: a DNS authoritative record\n";
    cout << "--auth(R)=<domain(F<n>)>,<type>,<class(F)>,<ttl(F)>,<rdatalen>,<rdata>: a DNS authoritative record\n";
    cout << "\n";
    cout << "--num-add=<n>: number of additional records (AF)\n";
    cout << "--additional(R)=<domain(F<n>)>,<type(F)>,<class(F)>,<ttl(F)>,<rdata>: a DNS additional record\n";
    cout << "--additional(R)=<domain(F<n>)>,<type(F)>,<class(F)>,<ttl(F)>,<rdatalen>,<rdata>: a DNS additional record\n";
    cout << "\n";
    cout << "--server=<port>: run in server mode on port (A)\n";
    cout << "\n";
    cout << "[MISC]\n";
    cout << "--num=<n>: number of packets (0 = infinite)\n";
    cout << "--delay=<usec>: delay between packets\n";
    cout << "--verbose: be verbose\n";
    cout << "--help: this help\n";
    cout << "\n";
}

void logger(string s)
{
    const time_t t = time(NULL);
    char buf[30];
    ctime_r(&t, buf);
    buf[strlen(buf)-1] = '\0';
    cout << "[" << buf << "] " << s << endl;
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
    DnsPacket p;
    uint16_t server_port = 0;
    Server* server = NULL;
    int type;
    ResourceRecord rr;

    memset(&forged_nrecords, 0x0, sizeof(forged_nrecords));

    cout << "\nDines " << PACKAGE_VERSION << " - The definitive DNS packet forger.\n\n";

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }

    if (getuid() != 0) {
        cout << "You need to be root." << endl;
        return 1;
    }

    vector<string> tokens;

    try {
        while((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
            switch(c) {
                case 0:
                    if (optarg[0] == 'F') {
                        p.fuzzSrcIp();
                    } else {
                        p.ipFrom(optarg);
                    }
                    break;

                case 1:
                    p.ipTo(optarg);
                    break;

                case 2:
                    if (optarg[0] == 'F') {
                        p.fuzzSport();
                    } else {
                        p.sport(optarg);
                    }
                    break;

                case 3:
                    p.dport(optarg);
                    break;

                case 4:
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzTxid();
                    } else {
                        p.txid(optarg);
                    }
                    break;

                case 5:
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzNRecord(Dines::R_QUESTION);
                    } else {
                        forged_nrecords[Dines::R_QUESTION] = atoi(optarg);
                    }
                    break;

                case 6:
                    tokens.clear();
                    tokens = tokenize(optarg, ",");

                    if (tokens.size() != 3) {
                        cout << "Syntax: --question <domain>,<type>,<class>\n";
                        return 1;
                    }

                    p.addQuestion(tokens.at(0), tokens.at(1), tokens.at(2));

                    if (tokens.at(0).at(0) == 'F') {
                        unsigned len = atoi(tokens.at(0).substr(1).data());
                        if (len == 0) {
                            cout << "Invalid format for fuzzer:\n";
                            cout << "F must be followed by fuzzed length\n";
                            cout << "Syntax: --question F<n>,<type>,<class>\n\n";
                            return 2;
                        }
                        DnsQuestion& q = p.question();
                        q.fuzzQdomain(len);
                    }
                    if (tokens.at(1) == "F") {
                        DnsQuestion& q = p.question();
                        q.fuzzQtype();
                    }
                    if (tokens.at(2) == "F") {
                        DnsQuestion& q = p.question();
                        q.fuzzQclass();
                    }
                    break;

                case 7:
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzNRecord(Dines::R_ANSWER);
                    } else {
                        forged_nrecords[Dines::R_ANSWER] = atoi(optarg);
                    }
                    break;

                case 8:
                case 10:
                case 12:
                    // c = 8 => type = 1
                    // c = 10 => type = 2
                    // c = 12 => type = 3
                    type = c / 2 - 3;
                    tokens.clear();
                    tokens = tokenize(optarg, ",");

                    if (tokens.size() < 5) {
                        cout << "Syntax:\n";
                        cout << "\t<domain>,<type>,<class>,<ttl>,<rdata>\n";
                        cout << "\t<domain>,<type>,<class>,<ttl>,<rdatalen>,<rdata>\n";
                        return 1;
                    }

                    if (tokens.size() == 6) {
                        const char* data = tokens.at(5).data();
                        rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2),
                            tokens.at(3), string(data, atoi(tokens.at(4).data())));
                    } else {
                        rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2),
                            tokens.at(3), Dines::rDataConvert(tokens.at(4).data(), tokens.at(1)));
                    }

                    if (tokens.at(0).at(0) == 'F') {
                        unsigned len = atoi(tokens.at(0).substr(1).data());
                        if (len == 0) {
                            cout << "Invalid format for fuzzer:\n";
                            cout << "F must be followed by fuzzed length\n";
                            cout << "Syntax: --question F<n>,<type>,<class>\n\n";
                            return 2;
                        }
                        rr.fuzzRRdomain(len);
                    }
                    if (tokens.at(1) == "F") {
                        rr.fuzzRRtype();
                    }
                    if (tokens.at(2) == "F") {
                        rr.fuzzRRclass();
                    }
                    if (tokens.at(3) == "F") {
                        rr.fuzzRRttl();
                    }

                    p.addRR(Dines::RecordSection(type), rr);
                    break;

                case 9:
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzNRecord(Dines::R_ADDITIONAL);
                    } else {
                        forged_nrecords[Dines::R_ADDITIONAL] = atoi(optarg);
                    }
                    break;

                case 11:
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzNRecord(Dines::R_AUTHORITIES);
                    } else {
                        forged_nrecords[Dines::R_AUTHORITIES] = atoi(optarg);
                    }
                    break;

                case 28:
                    p.isRecursive(false);
                    break;

                case 29:
                    if (optarg)
                        server_port = atoi(optarg);
                    else
                        server_port = 53;
                    break;
                case 30:
                    num = atoi(optarg);
                    break;

                case 31:
                    delay = atoi(optarg);
                    logger("Inter packet gap set to "  + string(optarg));
                    break;

                case 32:
                    logger("Verbose mode on");
                    p.setLogger(logger);
                    verbose = true;
                    break;
                default:
                    cout << "Unknown option: " << optarg << endl;
                    return 1;
            }
        }
    } catch(exception& e) {
        cerr << "Invalid parameter: " << e.what() << endl;
        return 2;
    }

    for (unsigned i = 0; i < 4; i++) {
        if (forged_nrecords[i] != 0) {
            p.nRecord(Dines::RecordSection(i), forged_nrecords[i]);
        }
    }

    // check if server has been created. In this case run it
    if (server_port > 0) {
        server = new Server(p, server_port);
        if (verbose == true)
            server->setLogger(logger);
        server->launch();
    }

    if (num == 0)
        num = 0xFFFFFFFF;

    cout << "Sending ";
    if (num < 0xFFFFFFFF)
        cout << num;
    else
        cout << "infinite";
    cout << " datagrams" << endl;

    // Send datagram
    while (num-- > 0) {
        p.fuzz();
        try {
            p.sendNet();
        } catch(exception& e) {
            cout << "\n\nError: " << e.what() << "\n";
            return 1;
        }

        if (!verbose) {
            cout << ".";
            cout.flush();
        }

        if (num > 0)
            usleep(delay);
    }
    cout << endl;
}
