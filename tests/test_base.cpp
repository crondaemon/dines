
#include <cppunit/Test.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestAssert.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestCaller.h>
#include <cppunit/extensions/HelperMacros.h>
#include <iostream>
#include <unistd.h>
#include <thread>

#include <utils.hpp>
#include <dns_packet.hpp>
#include <server.hpp>

using namespace std;

// A dummy log function to avoid output when running tests
bool log_done;
void dummylog(string s)
{
    log_done = true;
}

void run_server(Server* s)
{
    s->launch();
}

class DinesTest : public CppUnit::TestFixture {
public:
    void setUp()
    {
    }

    void tearDown()
    {
    }

    CPPUNIT_TEST_SUITE(DinesTest);
    CPPUNIT_TEST(test_ip);
    CPPUNIT_TEST(test_udp);
    CPPUNIT_TEST(test_header);
    CPPUNIT_TEST(test_question);
    CPPUNIT_TEST(test_rr);
    CPPUNIT_TEST(test_rr_tostring);
    CPPUNIT_TEST(test_query);
    CPPUNIT_TEST(test_answer);
    CPPUNIT_TEST(test_many_rr);
    CPPUNIT_TEST(test_raw_packet);
    CPPUNIT_TEST(test_fuzz_header);
    CPPUNIT_TEST(test_fuzz_question);
    CPPUNIT_TEST(test_fuzz_rr);
    CPPUNIT_TEST(test_fuzz_packet);
    CPPUNIT_TEST(test_invalid_section);
    CPPUNIT_TEST(test_conversion);
    CPPUNIT_TEST(test_ip_conversion);
    CPPUNIT_TEST(test_logging);
    CPPUNIT_TEST(test_copy_constructor_and_assignment);
    CPPUNIT_TEST(test_parse);
    CPPUNIT_TEST(test_packets);
    CPPUNIT_TEST(test_invalid);
    CPPUNIT_TEST(test_dns_packet);
    CPPUNIT_TEST(test_domain_decode);
    CPPUNIT_TEST(test_server_1);
    CPPUNIT_TEST(test_server_2);
    CPPUNIT_TEST(test_server_3);
    CPPUNIT_TEST(test_cksum);
    CPPUNIT_TEST(test_clear);
    CPPUNIT_TEST_SUITE_END();

    void test_ip()
    {
        DnsPacket p;
        p.from("1.2.3.4");
        p.to("2.3.4.5");
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), p.from());
        CPPUNIT_ASSERT_EQUAL(string("2.3.4.5"), p.to());
    }

    void test_udp()
    {
        DnsPacket p;
        p.sport("1000");
        p.dport("2000");
        CPPUNIT_ASSERT_EQUAL(uint16_t(1000), p.sport());
        CPPUNIT_ASSERT_EQUAL(uint16_t(2000), p.dport());
    }

    void test_header()
    {
        DnsHeader h1;

        CPPUNIT_ASSERT(h1.txid() != 0);
        CPPUNIT_ASSERT_EQUAL(uint16_t(0), h1.nRecord(Dines::R_QUESTION));
        CPPUNIT_ASSERT_EQUAL(uint16_t(0), h1.nRecord(Dines::R_ANSWER));
        CPPUNIT_ASSERT_EQUAL(uint16_t(0), h1.nRecord(Dines::R_ADDITIONAL));
        CPPUNIT_ASSERT_EQUAL(uint16_t(0), h1.nRecord(Dines::R_AUTHORITIES));

        DnsHeader h2(10, 1, 2, 3, 4);

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), h2.nRecord(Dines::R_QUESTION));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), h2.nRecord(Dines::R_ANSWER));
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), h2.nRecord(Dines::R_ADDITIONAL));
        CPPUNIT_ASSERT_EQUAL(uint16_t(4), h2.nRecord(Dines::R_AUTHORITIES));
        CPPUNIT_ASSERT_EQUAL(uint16_t(10), h2.txid());

        // qr flag
        CPPUNIT_ASSERT_EQUAL(true, h2.isQuestion());
        h2.isQuestion(true);
        CPPUNIT_ASSERT_EQUAL(true, h2.isQuestion());
        h2.isQuestion(false);
        CPPUNIT_ASSERT_EQUAL(false, h2.isQuestion());

        // rd flags
        CPPUNIT_ASSERT_EQUAL(true, h2.isRecursive());
        h2.isRecursive(true);
        CPPUNIT_ASSERT_EQUAL(true, h2.isRecursive());
        h2.isRecursive(false);
        CPPUNIT_ASSERT_EQUAL(false, h2.isRecursive());

        h2.txid(0x1234);
        CPPUNIT_ASSERT_EQUAL(uint16_t(0x1234), h2.txid());

        CPPUNIT_ASSERT_EQUAL(string("\x12\x34\x80\x00\x00\x01\x00\x02\x00\x04\x00\x03", 12), h2.data());

        DnsHeader h3;
        h3 = h2;

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), h3.nRecord(Dines::R_QUESTION));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), h3.nRecord(Dines::R_ANSWER));
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), h3.nRecord(Dines::R_ADDITIONAL));
        CPPUNIT_ASSERT_EQUAL(uint16_t(4), h3.nRecord(Dines::R_AUTHORITIES));
        CPPUNIT_ASSERT_EQUAL(uint16_t(0x1234), h3.txid());

        DnsHeader h4(h3);
        CPPUNIT_ASSERT_EQUAL(h4, h3);
        h3.txid(55);
        CPPUNIT_ASSERT(h4 != h3);
        h3.txid(h4.txid());
        h3.rd(1);
        CPPUNIT_ASSERT(h4 != h3);
        h3.rd(0);
        h3.nRecord(Dines::R_QUESTION, 2);
        CPPUNIT_ASSERT(h4 != h3);

        h3.rd(1);
        CPPUNIT_ASSERT_EQUAL(true, h3.rd());
        h3.ra(true);
        CPPUNIT_ASSERT_EQUAL(true, h3.ra());
        h3.ra(false);
        CPPUNIT_ASSERT_EQUAL(false, h3.ra());

        DnsHeader h5;
        char* buf = (char*)"\xaa\xbb\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        h5.parse(buf, 0);
        CPPUNIT_ASSERT_EQUAL(uint16_t(0xaabb), h5.txid());

        DnsPacket p;
        p.dnsHdr(h5);
        CPPUNIT_ASSERT_EQUAL(uint16_t(0xaabb), p.dnsHdr().txid());
    }

    void test_question()
    {
        DnsQuestion q1("www.test.com", 1, 1);
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), q1.qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q1.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q1.qclass());
        CPPUNIT_ASSERT_EQUAL(string("www.test.com/A/IN"), q1.to_string());

        DnsQuestion q2("www.test.com", "TXT", "CHAOS");
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), q2.qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(0x10), q2.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), q2.qclass());

        DnsQuestion q3;
        q3 = q1;
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), q3.qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q3.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q3.qclass());

        DnsQuestion q4(q2);
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), q4.qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(0x10), q4.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), q4.qclass());
        CPPUNIT_ASSERT_EQUAL(string("\x03\x77\x77\x77\x04\x74\x65\x73\x74\x03\x63\x6F\x6D\x00\x00\x10\x00\x03", 18), q4.data());

        DnsQuestion q5(q1);
        CPPUNIT_ASSERT_EQUAL(q1, q5);
        CPPUNIT_ASSERT(q1 != q4);
        q5.qtype(2);
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), q5.qtype());
        CPPUNIT_ASSERT_EQUAL(string("NS"), q5.qtypeStr());
        q5.qclass(2);
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), q5.qclass());
        CPPUNIT_ASSERT_EQUAL(string("CSNET"), q5.qclassStr());
        CPPUNIT_ASSERT(!q5.empty());

        DnsQuestion q6;
        CPPUNIT_ASSERT(q6.empty());
    }

    void test_rr()
    {
        ResourceRecord rr1("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");

        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), rr1.rrDomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), rr1.rrType());
        CPPUNIT_ASSERT_EQUAL(string("A"), rr1.rrTypeStr());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), rr1.rrClass());
        CPPUNIT_ASSERT_EQUAL(string("IN"), rr1.rrClassStr());
        CPPUNIT_ASSERT_EQUAL(uint32_t(64), rr1.ttl());
        CPPUNIT_ASSERT_EQUAL(uint32_t(4), rr1.rDataLen());
        rr1.rrDomain("www.test1.com");
        CPPUNIT_ASSERT_EQUAL(string("www.test1.com"), rr1.rrDomain());
        rr1.rrType("A");
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), rr1.rrType());
        rr1.rrClass("CHAOS");
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), rr1.rrClass());

        ResourceRecord rr2("www.test.com", 1, 1, 64, string("\x00\x00\x01\x00", 4));
        CPPUNIT_ASSERT_EQUAL(uint32_t(4), rr2.rDataLen());

        CPPUNIT_ASSERT_THROW(ResourceRecord rr3("Fnotvalid", 1, 1, 64, "\x01\x02\x03\x04"), runtime_error);

        // Test the fuzzer
        ResourceRecord rr4("F5", "F", "F", "F", "\x01\x02\x03\x04");
        string s1(rr4.rrDomain().data());
        rr4.fuzz();
        string s2(rr4.rrDomain().data());
        CPPUNIT_ASSERT(s1 != s2);
        rr4.fuzzRRtype();
        CPPUNIT_ASSERT(rr4.rrType() != rr4.fuzz().rrType());
    }

    void test_rr_tostring()
    {
        ResourceRecord rr1("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        CPPUNIT_ASSERT_EQUAL(string("www.test.com/A/IN/64/1.2.3.4"), rr1.to_string());

        rr1.rrType("NS");
        rr1.rData("ns.test.com");
        CPPUNIT_ASSERT_EQUAL(string("www.test.com/NS/IN/64"), rr1.to_string());
    }

    void test_query()
    {
        DnsPacket p1;
        p1.addQuestion("www.test.com", "A", "CHAOS");
        CPPUNIT_ASSERT_EQUAL(true, p1.isQuestion());
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), p1.question().qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), p1.question().qclass());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p1.question().qtype());
        CPPUNIT_ASSERT_EQUAL(true, p1.isRecursive());

        DnsPacket p2;
        p2.addQuestion(DnsQuestion("www.test.com", "A", "CHAOS"));
        p2.txid("1234");
        p2.isRecursive(false);

        CPPUNIT_ASSERT_EQUAL(uint16_t(1234), p2.txid());
        CPPUNIT_ASSERT_EQUAL(true, p2.isQuestion());
        CPPUNIT_ASSERT_EQUAL(false, p2.isRecursive());
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), p2.question().qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), p2.question().qclass());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p2.question().qtype());
    }

    void test_answer()
    {
        DnsPacket p;

        p.addQuestion("www.test.com", 1, 1);
        uint32_t addr = inet_addr("192.168.1.1");
        p.addRR(Dines::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p.nRecord(Dines::R_ANSWER));
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), p.answers(0).rrDomain());
        CPPUNIT_ASSERT_EQUAL(string("192.168.1.1"), p.answers(0).rData());
        CPPUNIT_ASSERT_EQUAL(uint32_t(64), p.answers(0).ttl());
        CPPUNIT_ASSERT_EQUAL(uint32_t(4), p.answers(0).rDataLen());

        addr = inet_addr("192.168.1.2");
        p.addRR(Dines::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), p.nRecord(Dines::R_ANSWER));
        p.nRecord(Dines::R_ANSWER, 3);
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), p.nRecord(Dines::R_ANSWER));

        CPPUNIT_ASSERT_THROW(p.addRR(Dines::RecordSection(77), ResourceRecord()), runtime_error);
    }

    void test_many_rr()
    {
        DnsPacket p;
        p.addQuestion("www.test.com", "A", "IN");
        ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        p.addRR(Dines::R_ANSWER, rr);
        rr.rrType("NS");
        p.addRR(Dines::R_ADDITIONAL, rr);
        rr.rrType("MX");
        p.addRR(Dines::R_AUTHORITIES, rr);

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p.nRecord(Dines::R_ADDITIONAL));
        CPPUNIT_ASSERT_EQUAL(Dines::stringToQtype("NS"), p.addRR(Dines::R_ADDITIONAL, rr).rrType());
        CPPUNIT_ASSERT_EQUAL(Dines::stringToQtype("NS"), p.additionals(0).rrType());

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p.nRecord(Dines::R_AUTHORITIES));
        CPPUNIT_ASSERT_EQUAL(Dines::stringToQtype("MX"), p.addRR(Dines::R_AUTHORITIES, rr).rrType());
        CPPUNIT_ASSERT_EQUAL(Dines::stringToQtype("MX"), p.authorities(0).rrType());

    }

    void test_raw_packet()
    {
        DnsPacket p1;
        p1.addQuestion("www.test.com", "A", "IN");
        p1.txid(0xd6e2);

        unsigned char pkt1[] = {
            0xd6, 0xe2, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x77, 0x77, 0x77, 0x04, 0x74, 0x65, 0x73,
            0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01 };

        CPPUNIT_ASSERT_EQUAL(string(pkt1, pkt1 + 30), p1.data());

        DnsPacket p2;
        p2.addQuestion("www.test.com", "A", "IN");
        p2.txid(0xdfc1);
        p2.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        p2.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x02\x03\x04\x05");

        unsigned char pkt2[] = {
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

        CPPUNIT_ASSERT_EQUAL(string(pkt2, pkt2 + 86), p2.data());
    }

    void test_fuzz_header()
    {
        DnsHeader h;

        h.txid(1);
        h.fuzz();
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), h.txid());

        h.fuzzFlags();

        DnsHeaderFlags flags = h.flags();
        h.fuzz();
        CPPUNIT_ASSERT(flags != h.flags());

        uint16_t nrecord;

        h.fuzzNRecord(0);
        h.fuzzNRecord(1);
        h.fuzzNRecord(2);
        h.fuzzNRecord(3);

        nrecord = h.nRecord(0);
        h.fuzz();
        CPPUNIT_ASSERT(nrecord != h.nRecord(0));
        nrecord = h.nRecord(1);
        h.fuzz();
        CPPUNIT_ASSERT(nrecord != h.nRecord(1));
        nrecord = h.nRecord(2);
        h.fuzz();
        CPPUNIT_ASSERT(nrecord != h.nRecord(2));

    }

    void test_fuzz_question()
    {
        DnsQuestion q1("F10", "F", "F");

        uint16_t x;

        string d = q1.qdomain();
        q1.fuzz();
        CPPUNIT_ASSERT(d != q1.qdomain());

        x = q1.qtype();
        q1.fuzz();
        CPPUNIT_ASSERT_EQUAL(x, q1.qtype());

        x = q1.qclass();
        q1.fuzz();
        CPPUNIT_ASSERT_EQUAL(x, q1.qclass());

        CPPUNIT_ASSERT_THROW(DnsQuestion("Ferror", "A", "IN"), runtime_error);

        DnsQuestion q2("www.test.com");
        CPPUNIT_ASSERT_EQUAL(false, q2.fuzzQtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q2.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q2.qclass());
        q2.fuzzQtype(true);
        q2.fuzzQclass(true);
        q2.fuzz();
        CPPUNIT_ASSERT(q2.qtype() != 1);
        CPPUNIT_ASSERT(q2.qclass() != 1);

    }

    void test_fuzz_rr()
    {
        ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");

        rr.fuzz();
        CPPUNIT_ASSERT_EQUAL(Dines::stringToQtype("A"), rr.rrType());

        rr.fuzzRRtype();
        rr.fuzzRRclass();
        rr.fuzzRRttl();

        uint16_t x;

        x = rr.rrType();
        rr.fuzz();
        CPPUNIT_ASSERT(x != rr.rrType());

        x = rr.rrClass();
        rr.fuzz();
        CPPUNIT_ASSERT(x != rr.rrClass());

        x = rr.ttl();
        rr.fuzz();
        CPPUNIT_ASSERT(x != rr.ttl());

    }

    void test_fuzz_packet()
    {
        DnsPacket p;
        p.addQuestion("www.test.com", "1", "1");
        ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        p.addRR(Dines::R_ANSWER, rr);
        p.addRR(Dines::R_AUTHORITIES, rr);
        p.addRR(Dines::R_ADDITIONAL, rr);

        p.dnsHdr().fuzzTxid();
        p.fuzzSrcIp();
        p.fuzzSport();
        uint16_t txid1 = p.txid();
        p.fuzz();
        uint16_t txid2 = p.txid();
        CPPUNIT_ASSERT(txid1 != txid2);
    }

    void test_invalid_section()
    {
        DnsHeader h;
        DnsPacket p;

        CPPUNIT_ASSERT_THROW(h.nRecord(7, 1), logic_error);
    //    CATCH_EXCEPTION(p.addRR(1, ResourceRecord("www.test.com", "A", "IN", "64", "abcd")));

    }

    void test_conversion()
    {
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQtype("A"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQtype("a"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), Dines::stringToQtype("NS"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), Dines::stringToQtype("ns"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(5), Dines::stringToQtype("CNAME"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(5), Dines::stringToQtype("cname"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(10), Dines::stringToQtype("NULL"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(10), Dines::stringToQtype("null"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(12), Dines::stringToQtype("PTR"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(12), Dines::stringToQtype("ptr"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(13), Dines::stringToQtype("HINFO"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(13), Dines::stringToQtype("hinfo"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(15), Dines::stringToQtype("MX"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(15), Dines::stringToQtype("mx"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(16), Dines::stringToQtype("TXT"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(16), Dines::stringToQtype("txt"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(252), Dines::stringToQtype("AXFR"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(252), Dines::stringToQtype("axfr"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQtype("ANY"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQtype("any"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQtype("F"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(20), Dines::stringToQtype("20"));
        CPPUNIT_ASSERT_THROW(Dines::stringToQtype("TEST"), logic_error);
        CPPUNIT_ASSERT_THROW(Dines::stringToQtype("70000"), runtime_error);

        CPPUNIT_ASSERT_EQUAL(string("A"), Dines::qtypeToString(1));
        CPPUNIT_ASSERT_EQUAL(string("NS"), Dines::qtypeToString(2));
        CPPUNIT_ASSERT_EQUAL(string("CNAME"), Dines::qtypeToString(5));
        CPPUNIT_ASSERT_EQUAL(string("NULL"), Dines::qtypeToString(10));
        CPPUNIT_ASSERT_EQUAL(string("PTR"), Dines::qtypeToString(12));
        CPPUNIT_ASSERT_EQUAL(string("HINFO"), Dines::qtypeToString(13));
        CPPUNIT_ASSERT_EQUAL(string("MX"), Dines::qtypeToString(15));
        CPPUNIT_ASSERT_EQUAL(string("TXT"), Dines::qtypeToString(16));
        CPPUNIT_ASSERT_EQUAL(string("AXFR"), Dines::qtypeToString(252));
        CPPUNIT_ASSERT_EQUAL(string("ANY"), Dines::qtypeToString(255));
        CPPUNIT_ASSERT_EQUAL(string("77"), Dines::qtypeToString(77));

        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQclass("IN"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQclass("in"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQclass("1"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), Dines::stringToQclass("CSNET"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), Dines::stringToQclass("csnet"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(2), Dines::stringToQclass("2"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), Dines::stringToQclass("CHAOS"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), Dines::stringToQclass("chaos"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(3), Dines::stringToQclass("3"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(4), Dines::stringToQclass("HESIOD"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(4), Dines::stringToQclass("hesiod"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(4), Dines::stringToQclass("4"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(254), Dines::stringToQclass("NONE"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(254), Dines::stringToQclass("none"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(254), Dines::stringToQclass("254"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQclass("ALL"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQclass("all"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQclass("ANY"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQclass("any"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(255), Dines::stringToQclass("255"));
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), Dines::stringToQclass("F"));
        CPPUNIT_ASSERT_THROW(Dines::stringToQclass("50"), runtime_error);

        CPPUNIT_ASSERT_EQUAL(string("IN"), Dines::qclassToString(1));
        CPPUNIT_ASSERT_EQUAL(string("CSNET"), Dines::qclassToString(2));
        CPPUNIT_ASSERT_EQUAL(string("CHAOS"), Dines::qclassToString(3));
        CPPUNIT_ASSERT_EQUAL(string("HESIOD"), Dines::qclassToString(4));
        CPPUNIT_ASSERT_EQUAL(string("NONE"), Dines::qclassToString(254));
        CPPUNIT_ASSERT_EQUAL(string("ANY"), Dines::qclassToString(255));
        CPPUNIT_ASSERT_EQUAL(string("7"), Dines::qclassToString(7));

        CPPUNIT_ASSERT_EQUAL(uint32_t(0x04030201), Dines::stringToIp32("1.2.3.4"));
        CPPUNIT_ASSERT_THROW(Dines::stringToIp32("1.2.not.good"), runtime_error);
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), Dines::ip32ToString(0x04030201));

        CPPUNIT_ASSERT_EQUAL(string("\x01\x02\x03\x04"), Dines::rDataConvert("1.2.3.4", 1));
        CPPUNIT_ASSERT_THROW(Dines::rDataConvert("1.2.not.good", 1), runtime_error);
        CPPUNIT_ASSERT_EQUAL(string("\x04test\x03""com\x00", 10), Dines::rDataConvert("test.com", 2));
        CPPUNIT_ASSERT_THROW(Dines::rDataConvert("test", 1), runtime_error);

    }

    void test_ip_conversion()
    {
        CPPUNIT_ASSERT_EQUAL(string("\x01\x02\x03\x04"), Dines::rDataConvert("1.2.3.4", 1));
    }

    void test_logging()
    {
        log_done = false;
        DnsPacket p;
        p.addQuestion("www.test.com", "a", "in");
        ResourceRecord rr("www.polito.it", "A", "IN", "64", "\x01\x02\x03\x04");
        p.addRR(Dines::R_ANSWER, rr);
        p.addRR(Dines::R_AUTHORITIES, rr);
        p.addRR(Dines::R_ADDITIONAL, rr);
        p.logger(dummylog);
        p.nRecord(Dines::R_ADDITIONAL, 1);
        CPPUNIT_ASSERT_EQUAL(true, log_done);
    }

    void test_copy_constructor_and_assignment()
    {
        DnsPacket p1;
        p1.from("1.2.3.4");
        DnsPacket p2(p1);
        DnsPacket p3;
        p3 = p1;
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), p2.from());
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), p3.from());
    }

    void test_parse()
    {
        DnsQuestion q;
        char* payload = (char*)"\x03www\x04test\x03""com\x00\x00\x01\x00\x01";
        q.parse(payload);
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), q.qdomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q.qtype());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), q.qclass());

        char* rrpayload = (char*)"\xd9\x63\x81\x80\x00\x01\x00\x02\x00\x02\x00\x00\x03\x77\x77\x77\x04\x74"
            "\x65\x73\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x09\x9d\x00"
            "\x10\x04\x74\x65\x73\x74\x08\x62\x6c\x6f\x63\x6b\x64\x6f\x73\xc0\x15\xc0\x2a\x00\x01\x00\x01"
            "\x00\x00\x00\x6f\x00\x04\xd0\x40\x79\xbc\xc0\x2f\x00\x02\x00\x01\x00\x00\x00\x6f\x00\x08\x05"
            "\x62\x6c\x63\x63\x31\xc0\x2f\xc0\x2f\x00\x02\x00\x01\x00\x00\x00\x6f\x00\x08\x05\x62\x6c\x63"
            "\x63\x32\xc0\x2f";

        ResourceRecord rr;
        rr.parse(rrpayload, 30);
        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), rr.rrDomain());

    }

    void test_packets()
    {
        DnsPacket p;
        CPPUNIT_ASSERT_EQUAL(uint32_t(1), p.packets());
        p.packets(0);
        CPPUNIT_ASSERT_EQUAL(uint32_t(0xFFFFFFFF), p.packets());
        CPPUNIT_ASSERT_EQUAL(string("infinite"), p.packetsStr());
        p.packets(10);
        CPPUNIT_ASSERT_EQUAL(uint32_t(10), p.packets());
        CPPUNIT_ASSERT_EQUAL(string("10"), p.packetsStr());
    }

    void test_invalid()
    {
        DnsPacket p;
        CPPUNIT_ASSERT_EQUAL(true, p.invalid());
        CPPUNIT_ASSERT_EQUAL(string("You must specify destination ip"), p.invalidMsg());
        p.to("1.2.3.4");
        CPPUNIT_ASSERT_EQUAL(false, p.invalid());
        CPPUNIT_ASSERT_EQUAL(string(""), p.invalidMsg());
    }

    void test_dns_packet()
    {
        DnsQuestion q("www.polito.it", "A", "IN");
        ResourceRecord rr("www.polito.it", "A", "IN", "64", "\x01\x02\x03\x04");
        DnsPacket p;
        p.from("1.2.3.4");
        p.sport("100");
        p.to("2.3.4.5");
        p.dport("53");
        p.txid("100");
        p.addQuestion(q);
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4:100 -> 2.3.4.5:53 txid: 0x64 Q NUM=1,0,0,0 [Question:www.polito.it/A/IN]"), p.to_string());
        p.addRR(Dines::R_ANSWER, rr);
        p.addRR(Dines::R_ADDITIONAL, rr);
        p.addRR(Dines::R_AUTHORITIES, rr);
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4:100 -> 2.3.4.5:53 txid: 0x64 R NUM=1,1,1,1 [Question:www.polito.it/A/IN][Answers:www.polito.it/A/IN/64/1.2.3.4][Authorities:www.polito.it/A/IN/64/1.2.3.4][Additionals:www.polito.it/A/IN/64/1.2.3.4]"), p.to_string());
        CPPUNIT_ASSERT_EQUAL(string("txid: 0x64 R NUM=1,1,1,1 [Question:www.polito.it/A/IN][Answers:www.polito.it/A/IN/64/1.2.3.4][Authorities:www.polito.it/A/IN/64/1.2.3.4][Additionals:www.polito.it/A/IN/64/1.2.3.4]"), p.to_string(true));
    }

    void test_domain_decode()
    {
        int b;
        string encoded;
        string decoded;

        char* buf1 = (char*)"\x03\x77\x77\x77\x06\x70\x6f\x6c\x69\x74\x6f\x02\x69\x74\x00";
        b = Dines::domainDecode(buf1, 0, encoded, decoded);
        CPPUNIT_ASSERT_EQUAL(string("www.polito.it"), decoded);
        CPPUNIT_ASSERT_EQUAL(string("\x03\x77\x77\x77\x06\x70\x6f\x6c\x69\x74\x6f\x02\x69\x74\x00", 15), encoded);
        CPPUNIT_ASSERT_EQUAL(15, b);

        char* buf2 = (char*)
            "\x4c\xa8\x81\x80\x00\x01\x00\x02\x00\x04"
            "\x00\x05\x03\x77\x77\x77\x06\x70\x6f\x6c"
            "\x69\x74\x6f\x02\x69\x74\x00\x00\x01\x00"
            "\x01\xc0\x0c\x00\x05\x00\x01\x00\x01\x4a"
            "\xdb\x00\x0a\x07\x77\x65\x62\x66\x61\x72"
            "\x6d\xc0\x10\xc0\x2b\x00\x01\x00\x01\x00"
            "\x01\x4a\xdb\x00\x04\x82\xc0\xb6\x21\xc0"
            "\x10\x00\x02\x00\x01\x00\x01\x4a\xdb\x00"
            "\x0b\x08\x6c\x65\x6f\x6e\x61\x72\x64\x6f"
            "\xc0\x10\xc0\x10\x00\x02\x00\x01\x00\x01"
            "\x4a\xdb\x00\x0e\x03\x6e\x73\x31\x04\x67"
            "\x61\x72\x72\x03\x6e\x65\x74\x00\xc0\x10"
            "\x00\x02\x00\x01\x00\x01\x4a\xdb\x00\x06"
            "\x03\x6e\x73\x33\xc0\x10\xc0\x10\x00\x02"
            "\x00\x01\x00\x01\x4a\xdb\x00\x08\x05\x67"
            "\x69\x6f\x76\x65\xc0\x10\xc0\x68\x00\x01"
            "\x00\x01\x00\x00\x5c\x9c\x00\x04\xc1\xce"
            "\x8d\x26\xc0\x68\x00\x1c\x00\x01\x00\x00"
            "\x5c\x9c\x00\x10\x20\x01\x07\x60\xff\xff"
            "\xff\xff\x00\x00\x00\x00\x00\x00\x00\xaa"
            "\xc0\x82\x00\x01\x00\x01\x00\x01\x4a\xdb"
            "\x00\x04\x82\xc0\x04\x1e\xc0\x94\x00\x01"
            "\x00\x01\x00\x01\x46\x95\x00\x04\x82\xc0"
            "\x03\x18\xc0\x51\x00\x01\x00\x01\x00\x01"
            "\x46\x95\x00\x04\x82\xc0\x03\x15";

        encoded = "";
        decoded = "";
        b = Dines::domainDecode(buf2, 12, encoded, decoded);
        CPPUNIT_ASSERT_EQUAL(string("www.polito.it"), decoded);
        CPPUNIT_ASSERT_EQUAL(15, b);

        encoded = "";
        decoded = "";
        b = Dines::domainDecode(buf2, 31, encoded, decoded);
        CPPUNIT_ASSERT_EQUAL(string("www.polito.it"), decoded);
        CPPUNIT_ASSERT_EQUAL(2, b);

        encoded = "";
        decoded = "";
        b = Dines::domainDecode(buf2, 53, encoded, decoded);
        CPPUNIT_ASSERT_EQUAL(string("webfarm.polito.it"), decoded);
        CPPUNIT_ASSERT_EQUAL(2, b);

        encoded = "";
        decoded = "";
        b = Dines::domainDecode(buf2, 92, encoded, decoded);
        CPPUNIT_ASSERT_EQUAL(string("polito.it"), decoded);
        CPPUNIT_ASSERT_EQUAL(2, b);

    }

    void test_server_1()
    {
        DnsPacket p1;
        Server s1(p1);
        s1.upstream(Dines::stringToIp32("127.0.0.1"), 10000);
        CPPUNIT_ASSERT_EQUAL(string("127.0.0.1"), s1.upstream());
        CPPUNIT_ASSERT(s1.invalid());
        CPPUNIT_ASSERT_EQUAL(string("--question and --upstream must be specified together in server mode"), s1.invalidMsg());

        DnsPacket p2;
        p2.addQuestion("www.test.com", "a", "in");
        Server s2(p2);
        s2.upstream(Dines::stringToIp32("127.0.0.1"), 10000);
        CPPUNIT_ASSERT(!s2.invalid());
        CPPUNIT_ASSERT_EQUAL(string(""), s2.invalidMsg());
    }

    void test_server_2()
    {
        uint16_t port = 20000;
        // Create a server
        DnsPacket answer;
        answer.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        Server server(answer, port);
        server.logger(dummylog);
        server.packets(1);

        std::thread server_th(run_server, &server);

        // Create a client
        DnsPacket query;
        query.addQuestion("www.test.com", "A", "IN");
        query.to("127.0.0.1");
        query.dport(port);

        // Wait for server to start
        while (!server.ready())
            ;

        DnsPacket* client_answer = query.sendNet();

        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), client_answer->answers(0).rrDomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), client_answer->answers(0).rrType());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), client_answer->answers(0).rrClass());
        CPPUNIT_ASSERT_EQUAL(uint32_t(64), client_answer->answers(0).ttl());
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), client_answer->answers(0).rData());

        server_th.join();

    }

    void test_server_3()
    {
        // In this test I'm going to create 2 servers and 1 client.
        // final: is the final server
        // relayer: is an intermediate server

        DnsPacket answer_test_com;
        answer_test_com.addRR(Dines::R_ANSWER, "www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        Server final_server(answer_test_com, 30000);
        final_server.logger(dummylog);
        final_server.packets(1);

        DnsPacket answer_another_record;
        answer_another_record.addRR(Dines::R_ANSWER, "another.record.com", "A", "IN", "64", "\x01\x02\x03\x04");
        Server relayer(answer_another_record, 20000);
        relayer.logger(dummylog);
        relayer.upstream(Dines::stringToIp32("127.0.0.1"), 30000);
        relayer.packets(1);

        std::thread final_server_th(run_server, &final_server);
        std::thread relayer_th(run_server,&relayer);

        DnsPacket query;
        query.addQuestion("www.test.com", "A", "IN");
        query.to("127.0.0.1");
        query.dport(20000);

        // Wait some time for servers setup
        while (!final_server.ready())
            ;
        while (!relayer.ready())
            ;

        DnsPacket* client_answer = query.sendNet();

        CPPUNIT_ASSERT_EQUAL(string("www.test.com"), client_answer->answers(0).rrDomain());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), client_answer->answers(0).rrType());
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), client_answer->answers(0).rrClass());
        CPPUNIT_ASSERT_EQUAL(uint32_t(64), client_answer->answers(0).ttl());
        CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), client_answer->answers(0).rData());

        final_server_th.join();
        relayer_th.join();

    }

    void test_cksum()
    {
        DnsPacket p;
        p.addQuestion("www.test.com", "a", "in");
        p.txid(1);
        p.doUdpCksum();
        CPPUNIT_ASSERT_EQUAL(uint16_t(0xc5a1), p.udpSum());
    }

    void test_clear()
    {
        DnsPacket p;
        p.addQuestion("www.test.com", "a", "in");
        ResourceRecord rr("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
        p.addRR(Dines::R_ANSWER, rr);
        p.addRR(Dines::R_AUTHORITIES, rr);
        p.addRR(Dines::R_ADDITIONAL, rr);
        CPPUNIT_ASSERT_EQUAL(uint16_t(1), p.nRecord(Dines::R_ADDITIONAL));
        p.clear();
        CPPUNIT_ASSERT_EQUAL(uint16_t(0), p.nRecord(Dines::R_ADDITIONAL));
    }
};

int main( int argc, char **argv)
{
    CppUnit::TextUi::TestRunner runner;
    runner.addTest(DinesTest::suite());
    runner.run();

    return 0;
}
