
#include <dns_packet.hpp>
#include <dns_header.hpp>
#include <iostream>

using namespace std;

#define TEST(func) { if ((func) != 0) return 1; }

#define CHECK(test) { \
    if (!(test)) { \
        cerr << "[ERROR] " << __FILE__ << ":" << __LINE__ << " (" << __func__ << ")" << endl; \
        return 1; \
    } \
    cout << "." << flush; \
}

int test_header()
{
    DnsPacket p;
    p.addQuestion("www.test.com", 1, 1);

    CHECK(p.dnsHdr.nrecord[DnsHeader::R_QUESTION] == 1);
    CHECK(p.dnsHdr.isQuestion() == true);
    CHECK(p.dnsHdr.isRecursive() == true);

    return 0;
}

int test_question()
{
    DnsQuestion q1("www.test.com", 1, 1);
    CHECK(q1.qdomain() == "www.test.com");
    CHECK(q1.qtype == 1);
    CHECK(q1.qclass == 1);

    DnsQuestion q2("www.test.com", "TXT", "CHAOS");
    CHECK(q2.qdomain() == "www.test.com");
    CHECK(q2.qtype == 0x10);
    CHECK(q2.qclass == 3);

    DnsQuestion q3;
    q3 = q1;
    CHECK(q3.qdomain() == "www.test.com");
    CHECK(q3.qtype == 1);
    CHECK(q3.qclass == 1);

    DnsQuestion q4(q2);
    CHECK(q4.qdomain() == "www.test.com");
    CHECK(q4.qtype == 0x10);
    CHECK(q4.qclass == 3);

    return 0;
}

int test_query()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "A", "CHAOS");
    CHECK(p.dnsHdr.isQuestion() == true);
    CHECK(p.question.qdomain() == "www.test.com");
    CHECK(p.question.qclass == 3);
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
    CHECK(p.answers.at(0).ttl == 64);
    return 0;
}

int main()
{
    cout << "Tests running";
    TEST(test_header());
    TEST(test_question());
    TEST(test_query());
    TEST(test_rr());
    cout << "done" << endl;
}
