
#include <dns_packet.hpp>
#include <debug.hpp>
#include <iostream>
#include <string.h>
#include <utils.hpp>

using namespace std;

#define TEST(func) { if ((func) != 0) return 1; }

#define CHECK(test) { \
    if (!(test)) { \
        cerr << "[ERROR] " << __FILE__ << ":" << __LINE__ << " (" << __func__ << ")\n"; \
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
        cerr << "[ERROR] " << __FILE__ << ":" << __LINE__ << " (" << __func__ << ")\n"; \
        return 1; \
    } \
    cout << "." << flush; \
}

// A dummy log function to avoid output when running tests
bool log_done;
void dummylog(string s)
{
    log_done = true;
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

int test_udp()
{
    DnsPacket p;
    p.sport("1000");
    p.dport("2000");
    CHECK(p.sport() == 1000);
    CHECK(p.dport() == 2000);
    return 0;
}

int test_header()
{
    DnsHeader h1;

    CHECK(h1.txid() != 0);
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

    CHECK(h2.data() == string("\x12\x34\x80\x00\x00\x01\x00\x02\x00\x04\x00\x03", 12));

    DnsHeader h3;
    h3 = h2;

    CHECK(h3.nRecord(Dines::R_QUESTION) == 1);
    CHECK(h3.nRecord(Dines::R_ANSWER) == 2);
    CHECK(h3.nRecord(Dines::R_ADDITIONAL) == 3);
    CHECK(h3.nRecord(Dines::R_AUTHORITIES) == 4);
    CHECK(h3.txid() == 0x1234);

    DnsHeader h4(h3);
    CHECK(h4 == h3);
    h3.txid(55);
    CHECK(h4 != h3);
    h3.txid(h4.txid());
    h3.rd(1);
    CHECK(h4 != h3);
    h3.rd(0);
    h3.nRecord(Dines::R_QUESTION, 2);
    CHECK(h4 != h3);

    h3.rd(1);
    CHECK(h3.rd() == true);
    h3.ra(true);
    CHECK(h3.ra() == true);
    h3.ra(false);
    CHECK(h3.ra() == false);

    return 0;
}

int test_question()
{
    DnsQuestion q1("www.test.com", 1, 1);
    CHECK(q1.qdomain() == "www.test.com");
    CHECK(q1.qtype() == 1);
    CHECK(q1.qclass() == 1);
    CHECK(q1.to_string() == "www.test.com/A/IN");

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

    DnsQuestion q5(q1);
    CHECK(q1 == q5);
    CHECK(q1 != q4);
    q5.qtype(2);
    CHECK(q5.qtype() == 2);
    CHECK(q5.qtypeStr() == "NS");
    q5.qclass(2);
    CHECK(q5.qclass() == 2);
    CHECK(q5.qclassStr() == "CSNET");
    CHECK(!q5.empty());

    DnsQuestion q6;
    CHECK(q6.empty());

    return 0;
}

int test_rr()
{
    ResourceRecord rr1("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");

    CHECK(rr1.rrDomain() == "www.test.com");
    CHECK(rr1.rrType() == 1);
    CHECK(rr1.rrTypeStr() == "A");
    CHECK(rr1.rrClass() == 1);
    CHECK(rr1.rrClassStr() == "IN");
    CHECK(rr1.ttl() == 64);
    CHECK(rr1.rDataLen() == 4);
    rr1.rrDomain("www.test1.com");
    CHECK(rr1.rrDomain() == "www.test1.com");
    rr1.rrType("A");
    CHECK(rr1.rrType() == 1);
    rr1.rrClass("CHAOS");
    CHECK(rr1.rrClass() == 3);

    ResourceRecord rr2("www.test.com", 1, 1, 64, string("\x00\x00\x01\x00", 4));
    CHECK(rr2.rDataLen() == 4);

    CATCH_EXCEPTION(ResourceRecord rr3("Fnotvalid", 1, 1, 64, "\x01\x02\x03\x04"));

    // Test the fuzzer
    ResourceRecord rr4("F5", "F", "F", "F", "\x01\x02\x03\x04");
    string s1(rr4.rrDomain().data());
    rr4.fuzz();
    string s2(rr4.rrDomain().data());
    CHECK(s1 != s2);
    rr4.fuzzRRtype();
    CHECK(rr4.rrType() != rr4.fuzz().rrType());

    return 0;
}

int test_rr_tostring()
{
    ResourceRecord rr1("www.test.com", "A", "IN", "64", "\x01\x02\x03\x04");
    CHECK(rr1.to_string() == "www.test.com/A/IN/64/1.2.3.4");

    rr1.rrType("NS");
    rr1.rData("ns.test.com");
    CHECK(rr1.to_string() == "www.test.com/NS/IN/64");

    return 0;
}

int test_query()
{
    DnsPacket p1;
    p1.addQuestion("www.test.com", "A", "CHAOS");
    CHECK(p1.isQuestion() == true);
    CHECK(p1.question().qdomain() == "www.test.com");
    CHECK(p1.question().qclass() == 3);
    CHECK(p1.question().qtype() == 1);
    CHECK(p1.isRecursive() == true);

    DnsPacket p2;
    p2.addQuestion(DnsQuestion("www.test.com", "A", "CHAOS"));
    p2.txid("1234");
    p2.isRecursive(false);

    CHECK(p2.txid() == 1234);
    CHECK(p2.isQuestion() == true);
    CHECK(p2.isRecursive() == false);
    CHECK(p2.question().qdomain() == "www.test.com");
    CHECK(p2.question().qclass() == 3);
    CHECK(p2.question().qtype() == 1);

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
    CHECK(p.answers(0).rData() == "192.168.1.1");
    CHECK(p.answers(0).ttl() == 64);
    CHECK(p.answers(0).rDataLen() == 4);

    addr = inet_addr("192.168.1.2");
    p.addRR(Dines::R_ANSWER, "www.test.com", 1, 1, 64, (const char*)&addr, 4);
    CHECK(p.nRecord(Dines::R_ANSWER) == 2);
    p.nRecord(Dines::R_ANSWER, 3);
    CHECK(p.nRecord(Dines::R_ANSWER) == 3);

    CATCH_EXCEPTION(p.addRR(Dines::RecordSection(77), ResourceRecord()));

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

    unsigned char pkt1[] = {
        0xd6, 0xe2, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01 };

    CHECK(p1.data() == string(pkt1, pkt1 + 30));

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

    CHECK(p2.data() == string(pkt2, pkt2 + 86));
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
    DnsQuestion q("F10", "F", "F");

    uint16_t x;

    string d = q.qdomain();
    q.fuzz();
    CHECK(d != q.qdomain());

    x = q.qtype();
    q.fuzz();
    CHECK(x != q.qtype());

    x = q.qclass();
    q.fuzz();
    CHECK(x != q.qclass());

    CATCH_EXCEPTION(DnsQuestion("Ferror", "A", "IN"));

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
    CHECK(Dines::stringToQtype("a") == 1);
    CHECK(Dines::stringToQtype("NS") == 2);
    CHECK(Dines::stringToQtype("ns") == 2);
    CHECK(Dines::stringToQtype("CNAME") == 5);
    CHECK(Dines::stringToQtype("cname") == 5);
    CHECK(Dines::stringToQtype("NULL") == 10);
    CHECK(Dines::stringToQtype("null") == 10);
    CHECK(Dines::stringToQtype("PTR") == 12);
    CHECK(Dines::stringToQtype("ptr") == 12);
    CHECK(Dines::stringToQtype("HINFO") == 13);
    CHECK(Dines::stringToQtype("hinfo") == 13);
    CHECK(Dines::stringToQtype("MX") == 15);
    CHECK(Dines::stringToQtype("mx") == 15);
    CHECK(Dines::stringToQtype("TXT") == 16);
    CHECK(Dines::stringToQtype("txt") == 16);
    CHECK(Dines::stringToQtype("AXFR") == 252);
    CHECK(Dines::stringToQtype("axfr") == 252);
    CHECK(Dines::stringToQtype("ANY") == 255);
    CHECK(Dines::stringToQtype("any") == 255);
    CHECK(Dines::stringToQtype("F") == 1);
    CHECK(Dines::stringToQtype("20") == 20);
    CATCH_EXCEPTION(Dines::stringToQtype("TEST"));
    CATCH_EXCEPTION(Dines::stringToQtype("70000"));

    CHECK(Dines::qtypeToString(1) == "A");
    CHECK(Dines::qtypeToString(2) == "NS");
    CHECK(Dines::qtypeToString(5) == "CNAME");
    CHECK(Dines::qtypeToString(10) == "NULL");
    CHECK(Dines::qtypeToString(12) == "PTR");
    CHECK(Dines::qtypeToString(13) == "HINFO");
    CHECK(Dines::qtypeToString(15) == "MX");
    CHECK(Dines::qtypeToString(16) == "TXT");
    CHECK(Dines::qtypeToString(252) == "AXFR");
    CHECK(Dines::qtypeToString(255) == "ANY");
    CHECK(Dines::qtypeToString(77) == "77");

    CHECK(Dines::stringToQclass("IN") == 1);
    CHECK(Dines::stringToQclass("in") == 1);
    CHECK(Dines::stringToQclass("1") == 1);
    CHECK(Dines::stringToQclass("CSNET") == 2);
    CHECK(Dines::stringToQclass("csnet") == 2);
    CHECK(Dines::stringToQclass("2") == 2);
    CHECK(Dines::stringToQclass("CHAOS") == 3);
    CHECK(Dines::stringToQclass("chaos") == 3);
    CHECK(Dines::stringToQclass("3") == 3);
    CHECK(Dines::stringToQclass("HESIOD") == 4);
    CHECK(Dines::stringToQclass("hesiod") == 4);
    CHECK(Dines::stringToQclass("4") == 4);
    CHECK(Dines::stringToQclass("NONE") == 254);
    CHECK(Dines::stringToQclass("none") == 254);
    CHECK(Dines::stringToQclass("254") == 254);
    CHECK(Dines::stringToQclass("ALL") == 255);
    CHECK(Dines::stringToQclass("all") == 255);
    CHECK(Dines::stringToQclass("ANY") == 255);
    CHECK(Dines::stringToQclass("any") == 255);
    CHECK(Dines::stringToQclass("255") == 255);
    CHECK(Dines::stringToQclass("F") == 1);
    CATCH_EXCEPTION(Dines::stringToQclass("50"));

    CHECK(Dines::qclassToString(1) == "IN");
    CHECK(Dines::qclassToString(2) == "CSNET");
    CHECK(Dines::qclassToString(3) == "CHAOS");
    CHECK(Dines::qclassToString(4) == "HESIOD");
    CHECK(Dines::qclassToString(254) == "NONE");
    CHECK(Dines::qclassToString(255) == "ANY");
    CHECK(Dines::qclassToString(7) == "7");

    CHECK(Dines::stringToIp32("1.2.3.4") == 0x04030201);
    CATCH_EXCEPTION(Dines::stringToIp32("1.2.not.good"));
    CHECK(Dines::ip32ToString(0x04030201) == "1.2.3.4");

    CHECK(Dines::rDataConvert("1.2.3.4", 1) == string("\x01\x02\x03\x04"));
    CATCH_EXCEPTION(Dines::rDataConvert("1.2.not.good", 1));
    CHECK(Dines::rDataConvert("test.com", 2) == string("\x04test\x03""com\x00", 10));
    CATCH_EXCEPTION(Dines::rDataConvert("test", 1));

    return 0;
}

int test_ip_conversion()
{
    CHECK(Dines::rDataConvert("1.2.3.4", 1) == "\x01\x02\x03\x04");
    return 0;
}

int test_logging()
{
    log_done = false;
    DnsPacket p;
    p.logger(dummylog);
    p.nRecord(Dines::R_ADDITIONAL, 1);
    CHECK(log_done == true);
    return 0;
}

int test_copy_constructor_and_assignment()
{
    DnsPacket p1;
    p1.ipFrom("1.2.3.4");
    DnsPacket p2(p1);
    DnsPacket p3;
    p3 = p1;
    CHECK(p2.ipFrom() == "1.2.3.4");
    CHECK(p3.ipFrom() == "1.2.3.4");
    return 0;
}

int test_parse()
{
    DnsQuestion q;
    char* payload = (char*)"\x03www\x04test\x03""com\x00\x00\x01\x00\x01";
    q.parse(payload);
    CHECK(q.qdomain() == "www.test.com");
    CHECK(q.qtype() == 1);
    CHECK(q.qclass() == 1);
    return 0;
}

int test_packets()
{
    DnsPacket p;
    CHECK(p.packets() == 0xFFFFFFFF);
    p.packets(0);
    CHECK(p.packets() == 0xFFFFFFFF);
    CHECK(p.packetsStr() == "infinite");
    p.packets(10);
    CHECK(p.packets() == 10);
    CHECK(p.packetsStr() == "10");
    return 0;
}

int test_invalid()
{
    DnsPacket p;
    CHECK(p.invalid() == true);
    CHECK(p.invalidMsg() == "You must specify destination ip");
    p.ipTo("1.2.3.4");
    CHECK(p.invalid() == false);
    CHECK(p.invalidMsg() == "");
    return 0;
}

int test_dns_packet()
{
    DnsQuestion q("www.polito.it", "A", "IN");
    ResourceRecord rr("www.polito.it", "A", "IN", "64", "\x01\x02\x03\x04");
    DnsPacket p;
    p.ipFrom("1.2.3.4");
    p.sport("100");
    p.ipTo("2.3.4.5");
    p.dport("53");
    p.txid("100");
    p.addQuestion(q);
    CHECK(p.to_string() == "1.2.3.4:100 -> 2.3.4.5:53 txid: 0x64 Q [Question:www.polito.it/A/IN]");
    p.addRR(Dines::R_ANSWER, rr);
    p.addRR(Dines::R_ADDITIONAL, rr);
    p.addRR(Dines::R_AUTHORITIES, rr);
    CHECK(p.to_string() == "1.2.3.4:100 -> 2.3.4.5:53 txid: 0x64 R [Question:www.polito.it/A/IN][Answers:www.polito.it/A/IN/64/1.2.3.4][Authorities:www.polito.it/A/IN/64/1.2.3.4][Additionals:www.polito.it/A/IN/64/1.2.3.4]");
    CHECK(p.to_string(true) == "txid: 0x64 R [Question:www.polito.it/A/IN][Answers:www.polito.it/A/IN/64/1.2.3.4][Authorities:www.polito.it/A/IN/64/1.2.3.4][Additionals:www.polito.it/A/IN/64/1.2.3.4]");
    return 0;
}

int test_domain_decode()
{
    int b;
    string encoded;
    string decoded;

    char* buf1 = (char*)"\x03\x77\x77\x77\x06\x70\x6f\x6c\x69\x74\x6f\x02\x69\x74\x00";
    b = Dines::domainDecode(buf1, 0, encoded, decoded);
    CHECK(decoded == "www.polito.it");
    CHECK(b == 15);

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
    CHECK(decoded == "www.polito.it");
    CHECK(b == 15);

    encoded = "";
    decoded = "";
    b = Dines::domainDecode(buf2, 31, encoded, decoded);
    CHECK(decoded == "www.polito.it");
    CHECK(b == 2);

    encoded = "";
    decoded = "";
    b = Dines::domainDecode(buf2, 53, encoded, decoded);
    CHECK(decoded == "webfarm.polito.it");
    CHECK(b == 2);

    encoded = "";
    decoded = "";
    b = Dines::domainDecode(buf2, 92, encoded, decoded);
    CHECK(decoded == "polito.it");
    CHECK(b == 2);

    return 0;
}

int main(int argc, char* argv[])
{
    cout << "Tests running";
    TEST(test_ip());
    TEST(test_udp());
    TEST(test_header());
    TEST(test_question());
    TEST(test_rr());
    TEST(test_rr_tostring());
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
    TEST(test_logging());
    TEST(test_copy_constructor_and_assignment());
    TEST(test_parse());
    TEST(test_packets());
    TEST(test_invalid());
    TEST(test_dns_packet());
    TEST(test_domain_decode());

    cout << "done" << "\n";
}
