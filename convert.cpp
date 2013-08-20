
#include <convert.hpp>

#include <tokenizer.hpp>

#include <vector>
#include <stdexcept>
#include <stdlib.h>
#include <iostream>
#include <arpa/inet.h>
#include <stdio.h>

using namespace std;

namespace Dines {

std::string domainEncode(const std::string& s)
{
    std::string out = "";
    std::vector<std::string> frags = tokenize(s, ".");

    for (std::vector<std::string>::const_iterator itr = frags.begin(); itr != frags.end(); ++itr) {
        // Add the len
        out.append(1, itr->length());
        // Add the frag
        out.append(*itr);
    }
    out.append(1, 0);

    return out;
}

// A reference for qtypes and qclasses
// http://edgedirector.com/app/type.htm

uint16_t stringToQtype(const std::string& s)
{
    if (s == "A") return 1;
    if (s == "NS") return 2;
    if (s == "CNAME") return 5;
    if (s == "NULL") return 10;
    if (s == "PTR") return 12;
    if (s == "HINFO") return 13;
    if (s == "MX") return 15;
    if (s == "TXT") return 16;
    if (s == "AXFR") return 252;
    if (s == "ANY") return 255;

    // this is used by fuzzer
    if (s == "F") return 1;

    unsigned n = atoi(s.c_str());

    if (n > 0xFFFF || n == 0) {
        throw runtime_error(string(__func__) + ": Invalid qtype");
    }

    return n;
}

string qtypeToString(uint16_t qtype)
{
    switch (qtype) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 5:
            return "CNAME";
        case 10:
            return "NULL";
        case 12:
            return "PTR";
        case 13:
            return "HINFO";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 252:
            return "AXFR";
        case 255:
            return "ANY";
        default:
            throw logic_error(string(__func__) + ": Invalid qtype");
    }
}

uint16_t stringToQclass(const std::string& s)
{
    if (s == "IN" || s == "1") return 0x0001;
    if (s == "CSNET" || s == "2") return 0x0002;
    if (s == "CHAOS" || s == "3") return 0x0003;
    if (s == "HESIOD" || s == "4") return 0x0004;
    if (s == "NONE" || s == "254") return 0x00fe;
    if (s == "ALL" || s == "ANY" || s == "255") return 0x00ff;

    if (s == "F") return 1;

    // Invalid class
    throw runtime_error(string(__func__) + ": Invalid qclass");
}

string qclassToString(uint16_t qclass)
{
    switch (qclass) {
        case 1:
            return "IN";
        case 2:
            return "CSNET";
        case 3:
            return "CHAOS";
        case 4:
            return "HESIOD";
        case 254:
            return "NONE";
        case 255:
            return "ANY";
        default:
            throw logic_error(string(__func__) + ": Invalid qclass");
    }
}

uint32_t stringToIp32(string s)
{
    uint32_t addr;
    if (inet_pton(AF_INET, s.data(), &addr) != 1)
        throw runtime_error("Can't convert IP address: " + s);
    return addr;
}

string ip32ToString(uint32_t ip32)
{
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &ip32, buf, INET_ADDRSTRLEN) == NULL) {
        throw runtime_error("Can't convert IP address");
    }
    return string(buf);
}

string rDataConvert(const char* opt, string qtype)
{
    if (qtype == "A") {
        struct in_addr addr;
        if (inet_pton(AF_INET, opt, &addr) == -1)
            throw runtime_error("Can't convert " + string(opt));
        return string((char*)&addr, 4);
    }

    if (qtype == "NS") {
        return domainEncode(opt);
    }

    throw runtime_error("Conversion of " + string(opt) + " not supported");
}

}; // namespace
