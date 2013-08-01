
#ifndef __CONVERT_HPP__
#define __CONVERT_HPP__

#include <string>
#include <stdint.h>

//! Encodes a string into a DNS domain name
std::string domainEncode(const std::string& s);

//! Converts a string into an integer qtype. It accepts both symbolic values, (as "TXT"),
//! and string numbers (as "1");
uint16_t stringToQtype(const std::string& s);

uint16_t stringToQclass(const std::string& s);

#endif
