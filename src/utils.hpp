
#ifndef __CONVERT_HPP__
#define __CONVERT_HPP__

#include <string>
#include <stdint.h>

namespace Dines {

typedef enum {
    R_QUESTION = 0,
    R_ANSWER = 1,
    R_ADDITIONAL = 2,
    R_AUTHORITIES = 3
} RecordSection;

typedef void (*LogFunc)(std::string);

//! Generate a random string of length
std::string random_string(size_t length);

//! Encodes a string into a DNS domain name
std::string domainEncode(const std::string& s);

//! Converts a string into an integer qtype. It accepts both symbolic values, (as "TXT"),
//! and string numbers (as "1");
uint16_t stringToQtype(const std::string& s);

std::string qtypeToString(uint16_t qtype);

uint16_t stringToQclass(const std::string& s);

std::string qclassToString(uint16_t qclass);

uint32_t stringToIp32(std::string s);

std::string ip32ToString(uint32_t ip32);

std::string rDataConvert(const char* opt, uint16_t qtype);

template<typename C> std::string convertInt(C i);

};

#endif
