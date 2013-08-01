
#include <dns_packet.hpp>
#include <dns_header.hpp>
#include <iostream>

using namespace std;

#define TEST(func) { if ((func()) != 0) return 1; }

#define CHECK(test) { \
    if (!(test)) { \
        fprintf(stderr, "[ERROR] func:%s line:%u\n", __func__, __LINE__); \
        return 1; \
    } \
    cout << "." << flush; \
}

int test_header()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "A", "1");

    CHECK(p.dnsHdr.nrecord[DnsHeader::R_QUESTION] == 1);
    CHECK(p.dnsHdr.question() == true);
    CHECK(p.dnsHdr.recursive() == true);

    return 0;
}

int test_question()
{
    DnsPacket p;
    p.addQuestion("www.test.com", 1, 1);
    CHECK(p.dnsHdr.question() == true);
    CHECK(p.question.qdomain() == "www.test.com");
    CHECK(p.question.qclass == 1);
    CHECK(p.question.qtype == 1);
    return 0;
}

int test_rr()
{
    DnsPacket p;

    p.addQuestion("www.test.com", 1, 1);
    uint32_t addr = inet_addr("192.168.1.1");
    p.addRR(DnsHeader::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);

    CHECK(p.dnsHdr.nrecord[DnsHeader::R_ANSWER] == 1);
    CHECK(p.answers.at(0).rrDomain() == "www.test.com");
    CHECK(*(unsigned*)p.answers.at(0).rdata.data() == 0x0101A8C0);
    return 0;
}

int main()
{
    cout << "Tests running";

    TEST(test_header);
    TEST(test_question);
    TEST(test_rr);
    cout << "done" << endl;
}
