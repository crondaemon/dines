
#include <cppunit/Test.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestAssert.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestCaller.h>
#include <cppunit/extensions/HelperMacros.h>
#include <iostream>
#include <unistd.h>

#include <dns_packet.hpp>

using namespace std;

class DinesRootTest : public CppUnit::TestFixture {
public:
    void setUp()
    {
    }

    void tearDown()
    {
    }

    CPPUNIT_TEST_SUITE(DinesRootTest);
    CPPUNIT_TEST(test_spoofing);
    CPPUNIT_TEST_SUITE_END();

    void test_spoofing()
    {
        DnsPacket p1;
        p1.addQuestion("www.test.com", "a", "in");
        p1.from("127.0.0.2");
        p1.to("127.0.0.1");

        DnsPacket* p2 = p1.sendNet();
        CPPUNIT_ASSERT_EQUAL((void*)NULL, (void*)p2);
    }
};

int main( int argc, char **argv)
{
    if (getuid() != 0) {
        cout << "You need to be root to run those tests\n";
        return 1;
    }

    CppUnit::TextUi::TestRunner runner;
    runner.addTest(DinesRootTest::suite());
    runner.run();

    return 0;
}
