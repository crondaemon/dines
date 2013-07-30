
#include <dns_packet.hpp>

#define TEST(func) { if ((func) != 0) return 1; }

#define CHECK(test) { \
    if (!(test)) { \
        fprintf(stderr, "[ERROR] func:%s line:%u\n", __func__, __LINE__); \
        return 1; \
    } \
}

int test_header()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "1", "1");

    CHECK(p.dnsHdr.nrecord[DnsHeader::R_QUESTION] == 1);
    CHECK(p.dnsHdr.question() == true);

    return 0;
}

int main()
{
    TEST(test_header());
}
