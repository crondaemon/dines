
#ifndef __CONVERT_HPP__
#define __CONVERT_HPP__

#include <string>
#include <stdint.h>
#include <stdexcept>

namespace Dines {

typedef enum {
    R_QUESTION = 0,
    R_ANSWER = 1,
    R_AUTHORITIES = 2,
    R_ADDITIONAL = 3
} RecordSection;

typedef enum {
    QTYPE_A = 1,
    QTYPE_NS = 2
} QTypes;

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

void logger(std::string s);

#ifdef DEBUG
std::string bufToHex(const char* buf, size_t len, std::string sep = ":");
std::string stringToHex(std::string source, std::string sep = ":");
#endif

//! Throws an exception for a given function, printing the errno as string
#define BASIC_EXCEPTION_THROW(function) \
    throw runtime_error(string(function) + "() error: " + strerror(errno));

};

#endif
