
#include <test.hpp>

int test_spoofing()
{
    DnsPacket p;
    p.addQuestion("www.test.com", "a", "in");
    p.from("127.0.0.2");
    p.to("127.0.0.1");

    // This packet will not get an aswer
    p.sendNet();
    return 0;
}

int main(int argc, char* argv[])
{
    if (getuid() != 0) {
        cout << "You need to be root to run those tests\n";
        return 1;
    }
    cout << "Tests running";
    TEST(test_spoofing());
    cout << "done" << "\n";
}
