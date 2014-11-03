
#include <dns_packet.hpp>
#include <debug.hpp>
#include <iostream>
#include <string.h>
#include <utils.hpp>
#include <server.hpp>
#include <unistd.h>
#include <signal.h>
#include <thread>

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
