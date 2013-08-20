
#include <dns_packet.hpp>
#include <debug.hpp>
#include <iostream>
#include <string.h>
#include <convert.hpp>
//#include <stdio.h>

using namespace std;

#define TEST(func) { if ((func) != 0) return 1; }

#define CHECK(test) { \
    if (!(test)) { \
        cerr << "[ERROR] " << __FILE__ << ":" << __LINE__ << " (" << __func__ << ")" << endl; \
        return 1; \
    } \
    cout << "." << flush; \
}

#define CATCH_EXCEPTION(statement) { \
    bool invalid = false; \
    try { \
        statement; \
    } catch(exception& e) { \
        invalid = true; \
    } \
    if (invalid == false) { \
        cerr << "[ERROR] " << __FILE__ << ":" << __LINE__ << " (" << __func__ << ")" << endl; \
        return 1; \
    } \
    cout << "." << flush; \
}

int test_ip()
{
    DnsPacket p;
    p.ipFrom("1.2.3.4");
    p.ipTo("2.3.4.5");
    CHECK(p.ipFrom() == "1.2.3.4");
    CHECK(p.ipTo() == "2.3.4.5");
    return 0;
}

int test_header()
{
    DnsHeader h1;

    CHECK(h1.txid() == 0);
    CHECK(h1.nRecord(Dines::R_QUESTION) == 0);
    CHECK(h1.nRecord(Dines::R_ANSWER) == 0);
    CHECK(h1.nRecord(Dines::R_ADDITIONAL) == 0);
    CHECK(h1.nRecord(Dines::R_AUTHORITIES) == 0);

    DnsHeader h2(10, 1, 2, 3, 4);

    CHECK(h2.nRecord(Dines::R_QUESTION) == 1);
    CHECK(h2.nRecord(Dines::R_ANSWER) == 2);
    CHECK(h2.nRecord(Dines::R_ADDITIONAL) == 3);
    CHECK(h2.nRecord(Dines::R_AUTHORITIES) == 4);
    CHECK(h2.txid() == 10);

    // qr flag
    CHECK(h2.isQuestion() == true);
    h2.isQuestion(true);
    CHECK(h2.isQuestion() == true);
    h2.isQuestion(false);
    CHECK(h2.isQuestion() == false);

    // rd flags
    CHECK(h2.isRecursive() == true);
    h2.isRecursive(true);
    CHECK(h2.isRecursive() == true);
    h2.isRecursive(false);
    CHECK(h2.isRecursive() == false);

    h2.txid(0x1234);
    CHECK(h2.txid() == 0x1234);

    CHECK(h2.data() == string("\x12\x34\x80\x00\x00\x01\x00\x02\x00\x03\x00\x04", 12));

    DnsHeader h3;
    h3 = h2;

    CHECK(h3.nRecord(Dines::R_QUESTION) == 1);
    CHECK(h3.nRecord(Dines::R_ANSWER) == 2);
    CHECK(h3.nRecord(Dines::R_ADDITIONAL) == 3);
    CHECK(h3.nRecord(Dines::R_AUTHORITIES) == 4);
    CHECK(h3.txid() == 0x1234);

    return 0;
}

int test_question()
{
    DnsQuestion q1("www.test.com", 1, 1);
    CHECK(q1.qdomain() == "www.test.com");
    CHECK(q1.qtype() == 1);
    CHECK(q1.qclass() == 1);

    DnsQuestion q2("www.test.com", "TXT", "CHAOS");
    CHECK(q2.qdomain() == "www.test.com");
    CHECK(q2.qtype() == 0x10);
    CHECK(q2.qclass() == 3);

    DnsQuestion q3;
    q3 = q1;
    CHECK(q3.qdomain() == "www.test.com");
    CHECK(q3.qtype() == 1);
    CHECK(q3.qclass() == 1);

    DnsQuestion q4(q2);
    CHECK(q4.qdomain() == "www.test.com");
    CHECK(q4.qtype() == 0x10);
    CHECK(q4.qclass() == 3);

    CHECK(q4.data() == string("\x03\x77\x77\x77\x04\x74\x65\x73\x74\x03\x63\x6F\x6D\x00\x00\x10\x00\x03", 18));

    return 0;
}

int test_rr()
{
    ResourceRecord rr1("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");

    CHECK(rr1.rrDomain() == "www.test.com");
    CHECK(rr1.rrType() == 1);
    CHECK(rr1.rrClass() == 1);
    CHECK(rr1.ttl() == 64);
    CHECK(rr1.rDataLen() == 4);

    rr1.rrType("A");
    CHECK(rr1.rrType() == 1);

    rr1.rrClass("CHAOS");
    CHECK(rr1.rrClass() == 3);

    ResourceRecord rr2("www.test.com", 1, 1, 64, string("\x00\x00\x01\x00", 4));
    CHECK(rr2.rDataLen() == 4);

    return 0;
}

int test_query()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "A", "CHAOS");
    CHECK(p.isQuestion() == true);
    CHECK(p.question().qdomain() == "www.test.com");
    CHECK(p.question().qclass() == 3);
    CHECK(p.question().qtype() == 1);
    CHECK(p.isRecursive() == true);
    return 0;
}

int test_answer()
{
    DnsPacket p;

    p.addQuestion("www.test.com", 1, 1);
    uint32_t addr = inet_addr("192.168.1.1");
    p.addRR(Dines::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);

    CHECK(p.nRecord(Dines::R_ANSWER) == 1);
    CHECK(p.answers(0).rrDomain() == "www.test.com");
    CHECK(*(unsigned*)p.answers(0).rData().data() == 0x0101A8C0);
    CHECK(p.answers(0).ttl() == 64);
    CHECK(p.answers(0).rDataLen() == 4);

    addr = inet_addr("192.168.1.2");
    p.addRR(Dines::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);
    CHECK(p.nRecord(Dines::R_ANSWER) == 2);
    p.nRecord(Dines::R_ANSWER, 3);
    CHECK(p.nRecord(Dines::R_ANSWER) == 3);
    return 0;
}

int test_many_rr()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "A", "IN");
    ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
    p.addRR(Dines::R_ANSWER, rr);
    rr.rrType("NS");
    p.addRR(Dines::R_ADDITIONAL, rr);
    rr.rrType("MX");
    p.addRR(Dines::R_AUTHORITIES, rr);

    CHECK(p.nRecord(Dines::R_ADDITIONAL) == 1);
    CHECK(p.addRR(Dines::R_ADDITIONAL, rr).rrType() == Dines::stringToQtype("NS"));
    CHECK(p.additionals(0).rrType() == Dines::stringToQtype("NS"));

    CHECK(p.nRecord(Dines::R_AUTHORITIES) == 1);
    CHECK(p.addRR(Dines::R_AUTHORITIES, rr).rrType() == Dines::stringToQtype("MX"));
    CHECK(p.authorities(0).rrType() == Dines::stringToQtype("MX"));

    return 0;
}

int test_raw_packet()
{
    DnsPacket p1;
    p1.addQuestion("www.test.com", "A", "IN");
    p1.txid(0xd6e2);

    char pkt1[] = {
        0xd6, 0xe2, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01 };

    CHECK(p1.data() == string(pkt1, 30));

    DnsPacket p2;
    p2.addQuestion("www.test.com", "A", "IN");
    p2.txid(0xdfc1);
    p2.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
    p2.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x02\x03\x04\x05");

    char pkt2[] = {
        0xdf, 0xc1, 0x81, 0x00,
        0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x04, 0x74,
        0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x03, 0x77,
        0x77, 0x77, 0x04, 0x74, 0x65, 0x73, 0x74, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x04, 0x02, 0x03,
        0x04, 0x05 };

    CHECK(p2.data() == string(pkt2, 86));
    return 0;
}

int test_fuzz_header()
{
    DnsHeader h;

    h.txid(1);
    h.fuzz();
    CHECK(h.txid() == 1);

    h.fuzzFlags();

    DnsHeaderFlags flags = h.flags();
    h.fuzz();
    CHECK(flags != h.flags());

    uint16_t nrecord;

    h.fuzzNRecord(0);
    h.fuzzNRecord(1);
    h.fuzzNRecord(2);
    h.fuzzNRecord(3);

    nrecord = h.nRecord(0);
    h.fuzz();
    CHECK(nrecord != h.nRecord(0));
    nrecord = h.nRecord(1);
    h.fuzz();
    CHECK(nrecord != h.nRecord(1));
    nrecord = h.nRecord(2);
    h.fuzz();
    CHECK(nrecord != h.nRecord(2));

    return 0;
}

int test_fuzz_question()
{
    DnsQuestion q("www.test.com", "A", "IN");
    q.fuzzQtype();
    q.fuzzQclass();

    uint16_t x;

    x = q.qtype();
    q.fuzz();
    CHECK(x != q.qtype());

    x = q.qclass();
    q.fuzz();
    CHECK(x != q.qclass());

    return 0;
}

int test_fuzz_rr()
{
    ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");

    rr.fuzz();
    CHECK(rr.rrType() == Dines::stringToQtype("A"));

    rr.fuzzRRtype();
    rr.fuzzRRclass();
    rr.fuzzRRttl();

    uint16_t x;

    x = rr.rrType();
    rr.fuzz();
    CHECK(x != rr.rrType());

    x = rr.rrClass();
    rr.fuzz();
    CHECK(x != rr.rrClass());

    x = rr.ttl();
    rr.fuzz();
    CHECK(x != rr.ttl());

    return 0;
}

int test_fuzz_packet()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "1", "1");
    DnsHeader& h = p.dnsHdr();
    h.fuzzTxid();
    uint16_t txid1 = p.txid();
    p.fuzz();
    uint16_t txid2 = p.txid();
    CHECK(txid1 != txid2);
    return 0;
}

int test_invalid_section()
{
    DnsHeader h;
    DnsPacket p;

    CATCH_EXCEPTION(h.nRecord(7, 1));
//    CATCH_EXCEPTION(p.addRR(1, ResourceRecord("www.test.com", "A", "IN", "64", "abcd")));

    return 0;
}

int test_conversion()
{
    CHECK(Dines::stringToQtype("A") == 1);
    CHECK(Dines::stringToQtype("NS") == 2);
    CHECK(Dines::stringToQtype("CNAME") == 5);
    CHECK(Dines::stringToQtype("PTR") == 12);
    CHECK(Dines::stringToQtype("HINFO") == 13);
    CHECK(Dines::stringToQtype("MX") == 15);
    CHECK(Dines::stringToQtype("TXT") == 16);
    CHECK(Dines::stringToQtype("AXFR") == 252);
    CHECK(Dines::stringToQtype("ANY") == 255);
    CHECK(Dines::stringToQtype("F") == 1);
    CHECK(Dines::stringToQtype("20") == 20);
    CATCH_EXCEPTION(Dines::stringToQtype("TEST"));
    CATCH_EXCEPTION(Dines::stringToQtype("70000"));

    CHECK(Dines::stringToQclass("IN") == 1);
    CHECK(Dines::stringToQclass("CSNET") == 2);
    CHECK(Dines::stringToQclass("2") == 2);
    CHECK(Dines::stringToQclass("CHAOS") == 3);
    CHECK(Dines::stringToQclass("3") == 3);
    CHECK(Dines::stringToQclass("HESIOD") == 4);
    CHECK(Dines::stringToQclass("4") == 4);
    CHECK(Dines::stringToQclass("NONE") == 254);
    CHECK(Dines::stringToQclass("254") == 254);
    CHECK(Dines::stringToQclass("ALL") == 255);
    CHECK(Dines::stringToQclass("ANY") == 255);
    CHECK(Dines::stringToQclass("255") == 255);
    CHECK(Dines::stringToQclass("4") == 4);
    CHECK(Dines::stringToQclass("F") == 1);
    CATCH_EXCEPTION(Dines::stringToQclass("50"));

    return 0;
}

int test_ip_conversion()
{
    // XXX
    return 0;
}

int main(int argc, char* argv[])
{
    cout << "Tests running";
    TEST(test_ip());
    TEST(test_header());
    TEST(test_question());
    TEST(test_rr());
    TEST(test_query());
    TEST(test_answer());
    TEST(test_many_rr());
    TEST(test_raw_packet());
    TEST(test_fuzz_header());
    TEST(test_fuzz_question());
    TEST(test_fuzz_rr());
    TEST(test_fuzz_packet());
    TEST(test_invalid_section());
    TEST(test_conversion());
    TEST(test_ip_conversion());
    cout << "done" << endl;
}
