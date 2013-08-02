
#include <convert.hpp>

#include <tokenizer.hpp>

#include <vector>
#include <stdexcept>
#include <stdlib.h>
#include <iostream>

using namespace std;

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
    if (s == "PTR") return 12;
    if (s == "HINFO") return 13;
    if (s == "MX") return 15;
    if (s == "TXT") return 16;
    if (s == "AXFR") return 252;
    if (s == "ANY") return 255;

    unsigned n = atoi(s.c_str());

    if (n > 0xFFFF || n == 0) {
        throw runtime_error("Invalid qtype");
    }

    return n;
}

uint16_t stringToQclass(const std::string& s)
{
    if (s == "IN" || s == "1") return 0x0001;
    if (s == "CSNET" || s == "2") return 0x0002;
    if (s == "CHAOS" || s == "3") return 0x0003;
    if (s == "HESIOD" || s == "4") return 0x0004;
    if (s == "NONE" || s == "254") return 0x00fe;
    if (s == "ALL" || s == "ANY" || s == "255") return 0x00ff;

    // Invalid class
    throw runtime_error("Invalid qclass");
}
