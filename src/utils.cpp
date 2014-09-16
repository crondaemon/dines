
#include <utils.hpp>

#include <tokenizer.hpp>
#include <debug.hpp>

#include <vector>
#include <stdexcept>
#include <stdlib.h>
#include <iostream>
#include <arpa/inet.h>
#include <stdio.h>
#include <typeinfo>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <string.h>

using namespace std;

namespace Dines {

static std::vector<char> charset()
{
    return vector<char>(
    {'0','1','2','3','4',
    '5','6','7','8','9',
    'A','B','C','D','E','F',
    'G','H','I','J','K',
    'L','M','N','O','P',
    'Q','R','S','T','U',
    'V','W','X','Y','Z',
    'a','b','c','d','e','f',
    'g','h','i','j','k',
    'l','m','n','o','p',
    'q','r','s','t','u',
    'v','w','x','y','z'
    });
};

// Internal randon string generator
static std::string random_string_int( size_t length, std::function<char(void)> rand_char )
{
    std::string str(length, 0);
    std::generate_n(str.begin(), length, rand_char);
    return str;
}

std::string random_string(size_t length)
{
    const auto ch_set = charset();
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, ch_set.size()-1);
    auto randchar = [ch_set,&dist,&rng ](){return ch_set[ dist(rng) ];};
    return random_string_int(length, randchar);
}

std::string domainEncode(const std::string s)
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

unsigned domainDecode(char* base, unsigned offset, std::string& encoded, std::string & decoded)
{
    uint16_t jump;
    unsigned len;

    if (base[offset] == '\0') {
        if (decoded.size() > 0)
            decoded.erase(decoded.size() - 1, decoded.size());
        return 1;
    }

    if (((u_char*)base)[offset] >> 6 == 3) {
        // Compressed
        memcpy(&jump, base + offset, 2);
        jump = ntohs(jump);
        jump = (jump & 0x3FFF);
        len = base[jump];
        encoded += string(base + jump, len + 1);
        decoded += string(base + jump + 1, len) + ".";
        domainDecode(base, jump + 1 + len, encoded, decoded);
        return 2;
    } else {
        // Not compressed
        len = base[offset];
        encoded += string(base + offset, len + 1);
        decoded += string(base + 1 + offset, len) + ".";
        return (len + 1 + domainDecode(base, offset + 1 + len, encoded, decoded));
    }
}

// A reference for qtypes and qclasses
// http://edgedirector.com/app/type.htm

uint16_t stringToQtype(const std::string s)
{
    if (s == "A" || s == "a") return 1;
    if (s == "NS" || s == "ns") return 2;
    if (s == "CNAME" || s == "cname") return 5;
    if (s == "NULL" || s == "null") return 10;
    if (s == "PTR" || s == "ptr") return 12;
    if (s == "HINFO" || s == "hinfo") return 13;
    if (s == "MX" || s == "mx") return 15;
    if (s == "TXT" || s == "txt") return 16;
    if (s == "AXFR" || s == "axfr") return 252;
    if (s == "ANY" || s == "any") return 255;

    // this is used by fuzzer
    if (s == "F" || s == "") {
        return 1;
    }

    unsigned n = std::stoul(s);

    if (n > 65535) {
        throw runtime_error(string(__func__) + "(): Invalid qtype " + s);
    }

    return n;
}

string qtypeToString(uint16_t qtype)
{
    char num[6];
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
            snprintf(num, 6, "%u", qtype);
            return string(num);
    }
}

uint16_t stringToQclass(const std::string s)
{
    if (s == "IN" || s == "in" || s == "1") return 0x0001;
    if (s == "CSNET" || s == "csnet" || s == "2") return 0x0002;
    if (s == "CHAOS" || s == "chaos" || s == "3") return 0x0003;
    if (s == "HESIOD" || s == "hesiod" || s == "4") return 0x0004;
    if (s == "NONE" || s == "none" || s == "254") return 0x00fe;
    if (s == "ALL" || s == "all" || s == "any" || s == "ANY" || s == "255") return 0x00ff;

    if (s == "F") return 1;

    if (s == "") return 1;

    // Invalid class
    throw runtime_error(string(__func__) + ": Invalid qclass " + s);
}

string qclassToString(uint16_t qclass)
{
    char num[6];
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
            snprintf(num, 6, "%u", qclass);
            return string(num);
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
    inet_ntop(AF_INET, &ip32, buf, INET_ADDRSTRLEN);
    return string(buf);
}

string rDataConvert(const char* opt, uint16_t qtype)
{
    if (qtype == 1) {
        struct in_addr addr;
        if (inet_pton(AF_INET, opt, &addr) != 1)
            throw runtime_error("Can't convert " + string(opt));
        return string((char*)&addr, 4);
    }

    if (qtype == 2) {
        return domainEncode(opt);
    }

    throw runtime_error("Conversion of " + string(opt) + " not supported");
}

std::string toHex(uint32_t value)
{
    std::ostringstream oss;
    if (!(oss<<std::hex<<value))
        throw logic_error("Invalid argument");
    return oss.str();
}

}; // namespace
