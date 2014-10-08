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
#include <utils.hpp>

using namespace std;

#define PRINT_DOT(x) { if (!verbose) { cout << "."; cout.flush(); } }

struct option opts[] = {
    {"src-ip", 1, NULL, 0},
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
    {"upstream", 1, NULL, 13},
    // some space here for new params
    {"no-rd", 0, NULL, 28},
    {"server", 2, NULL, 29},
    {"num", 1, NULL, 30},
    {"delay", 1, NULL, 31},
    {"verbose", 0, NULL, 32},
    {"help", 0, NULL, 33},
    {NULL, 0, NULL, 0}
};

void usage(string s)
{
    cout << "Fields with (F) can be fuzzed. (Example --txid F)\n";
    cout << "Fields with (F<n>) can be fuzzed for a specific length (Example --question F20,A,IN)\n";
    cout << "Fields with (R) are repeatable. (Example --answer)\n";
    cout << "Fields with (A) are calculated automatically.\n";
    cout << "\n";
    cout << "Usage:\n";
    cout << "\tCLIENT MODE: " << s << " [<params>] <dns server>\n";
    cout << "\tSERVER MODE: " << s << " [<params>] --server=<port>\n";
    cout << "\n";
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
    cout << "--auth(R)=<domain|F<n>>,<type>,<class(F)>,<ttl(F)>,<rdata>: a DNS authoritative record\n";
    cout << "--auth(R)=<domain|F<n>>,<type>,<class(F)>,<ttl(F)>,<rdatalen>,<rdata>: a DNS authoritative record\n";
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
    cout << "\nExamples:\n";
    cout << "\t./dines --question=www.example.com 1.2.3.4\n";
    cout << "\tsudo ./dines --server\n";
    cout << "\tsudo ./dines --server --answer=www.example.com,A,IN,64,1.2.3.4\n";
    cout << "\tsudo ./dines --server --question www.example.com --answer www.example.com,A,IN,64,1.2.3.4 --upstream --verbose\n";
    cout << "\n";
}

int main(int argc, char* argv[])
{
    int c = 0;
    string qtype = "";
    string qclass = "";
    unsigned num = 0;
    struct timespec delay = { .tv_sec = 1, .tv_nsec = 0 };
    bool verbose = false;
    vector<int> forged_nrecords(4, 0);
    DnsPacket p;
    uint16_t server_port = 0;
    int type;
    ResourceRecord rr;
    unsigned temp;
    vector<string> tokens;
    uint32_t upstream = 0;

    cout << "\nDines " << PACKAGE_VERSION << " - The definitive DNS packet forger.\n\n";

    if (argc == 1) {
        usage(argv[0]);
        return 1;
    }

    // first, scan the argv looking for verbose mode
    for (int i = 0; i < argc; i++) {
        if (string(argv[i]) == "--verbose") {
            Dines::logger("Verbose mode on");
            p.logger(Dines::logger);
            verbose = true;
        }
    }

    try {
        while((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
            switch(c) {
                case 0: // src-ip
                    if (optarg[0] == 'F') {
                        p.fuzzSrcIp();
                    } else {
                        p.from(optarg);
                    }
                    break;

                case 2: // sport
                    if (optarg[0] == 'F') {
                        p.fuzzSport();
                    } else {
                        p.sport(optarg);
                    }
                    break;

                case 3: // dport
                    p.dport(optarg);
                    break;

                case 4: // txid
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzTxid();
                    } else {
                        p.txid(optarg);
                    }
                    break;

                case 5: // num-questions
                    if (optarg[0] == 'F') {
                        DnsHeader& h = p.dnsHdr();
                        h.fuzzNRecord(Dines::R_QUESTION);
                    } else {
                        forged_nrecords.at(Dines::R_QUESTION) = stoul(optarg);
                    }
                    break;

                case 6: // question
                    tokens.clear();
                    tokens = tokenize(optarg, ",");
                    tokens.resize(3);

                    p.addQuestion(tokens.at(0), tokens.at(1), tokens.at(2));
                    break;

                case 8: // answer
                case 10: // auth
                case 12: // additional
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
                            tokens.at(3), string(data, stoul(tokens.at(4).data())));
                    } else {
                        rr = ResourceRecord(tokens.at(0), tokens.at(1), tokens.at(2),
                            tokens.at(3), Dines::rDataConvert(tokens.at(4).data(), Dines::stringToQtype(tokens.at(1))));
                    }

                    p.addRR(Dines::RecordSection(type), rr);
                    break;

                case 7: // num-answers
                    if (optarg[0] == 'F') {
                        p.dnsHdr().fuzzNRecord(Dines::R_ANSWER);
                    } else {
                        forged_nrecords.at(Dines::R_ANSWER) = stoul(optarg);
                    }
                    break;

                case 9: // num-auth
                    if (optarg[0] == 'F') {
                        p.dnsHdr().fuzzNRecord(Dines::R_ADDITIONAL);
                    } else {
                        forged_nrecords.at(Dines::R_ADDITIONAL) = stoul(optarg);
                    }
                    break;

                case 11: // num-additional
                    if (optarg[0] == 'F') {
                        p.dnsHdr().fuzzNRecord(Dines::R_AUTHORITIES);
                    } else {
                        forged_nrecords.at(Dines::R_AUTHORITIES) = stoul(optarg);
                    }
                    break;

                case 13: // upstream
                    upstream = Dines::stringToIp32(optarg);
                    break;

                case 28: // no-rd
                    p.isRecursive(false);
                    break;

                case 29: // server
                    if (optarg)
                        server_port = stoul(optarg);
                    else
                        server_port = 53;
                    break;
                case 30: // num
                    num = stoul(optarg);
                    break;

                case 31: // delay
                    temp = stoul(optarg);
                    delay = { .tv_sec = temp / 1000000, .tv_nsec = temp % 1000000 };
                    Dines::logger(string("Inter packet gap set to ")  + std::to_string(delay.tv_sec) +
                        " sec, " + std::to_string(delay.tv_nsec) + " nsec");
                    break;

                case 32: // verbose (already processed)
                    break;

                case 33: // help
                    usage(argv[0]);
                    return 0;

                default:
                    cout << "Unknown option: " << optarg << endl;
                    return 1;
            }
        }
    } catch(exception& e) {
        cerr << "Invalid parameter: " << e.what() << endl;
        return 2;
    }

#ifndef DEBUG
    try {
#endif
        // We are forging the number of records. We need to explicitly set them after options processing
        for (unsigned i = 0; i < 4; i++) {
            if (forged_nrecords.at(i) != 0) {
                p.nRecord(Dines::RecordSection(i), forged_nrecords.at(i));
            }
        }

        if (server_port > 0) {
            // Server mode
            if (argc != optind) {
                cerr << "When running in server mode you can't specify server destination address" << endl;
                return 1;
            }

            p.to("255.255.255.255");

            if (p.invalid()) {
                cerr << "Invalid parameters:\n\n";
                cerr << p.invalidMsg() << endl;
                return 1;
            }

            Server server(p, server_port);

            if (verbose == true)
                server.logger(Dines::logger);

            if (upstream > 0)
                server.upstream(upstream);

            if (server.invalid()) {
                cerr << "Invalid parameters:\n\n";
                cerr << server.invalidMsg() << endl;
                return 1;
            }

            // Set the number of packets
            if (num > 0)
                server.packets(num);

            server.launch();
        } else {
            // Client mode

            if (argc == optind) {
                cerr << "You must specify the server destination address" << endl;
                return 1;
            }

            // The rest of the cmdline contains the addresses to scan
            p.to(argv[optind]);

            // Set the packets to send
            if (num > 0)
                p.packets(num);

            if (p.invalid()) {
                cerr << "Invalid parameters:\n\n";
                cerr << p.invalidMsg() << endl;
                return 1;
            }

            Dines::logger(string("Sending ") + p.packetsStr() + " datagram" + (p.packets() > 1 ? "s" : ""));

            while (p.packets() > 0) {
                p.fuzz();
                p.sendNet();

                if (!verbose)
                    PRINT_DOT();

                if (p.packets() > 0)
                    nanosleep(&delay, NULL);
            }
            cout << "\n";
        }
#ifndef DEBUG
    } catch(exception& e) {
        Dines::logger(string("Runtime error: ") + e.what());
        return 1;
    }
#endif
    return 0;
}
