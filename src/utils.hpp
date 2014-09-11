
#ifndef __CONVERT_HPP__
#define __CONVERT_HPP__

#include <string>
#include <stdint.h>

namespace Dines {

typedef enum {
    R_QUESTION = 0,
    R_ANSWER = 1,
    R_AUTHORITIES = 2,
    R_ADDITIONAL = 3
} RecordSection;

typedef void (*LogFunc)(std::string);

//! Generate a random string of length
std::string random_string(size_t length);

//! Encodes a string into a DNS domain name
std::string domainEncode(const std::string s);

//! Decodes a DNS domain name into a string
unsigned domainDecode(char* base, unsigned offset, std::string& encoded, std::string & decoded);

//! Converts a string into an integer qtype. It accepts both symbolic values, (as "TXT"),
//! and string numbers (as "1");
uint16_t stringToQtype(const std::string s);

std::string qtypeToString(uint16_t qtype);

uint16_t stringToQclass(const std::string s);

std::string qclassToString(uint16_t qclass);

uint32_t stringToIp32(std::string s);

std::string ip32ToString(uint32_t ip32);

std::string rDataConvert(const char* opt, uint16_t qtype);

std::string toHex(uint32_t value);

std::string ipToString(uint32_t ip);

};

#endif
