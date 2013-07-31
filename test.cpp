
#include <dns_packet.hpp>
#include <iostream>

using namespace std;

#define TEST(func) { if ((func) != 0) return 1; }

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
    p.addQuestion("www.test.com", "1", "1");

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
    return 0;
}

int main()
{
    cout << "Tests running";
    TEST(test_header());
    TEST(test_question());
    cout << "done" << endl;
}
