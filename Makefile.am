bin_PROGRAMS = dines test_dines
AUTOMAKE_OPTIONS = subdir-objects
dines_SOURCES = src/debug.hpp src/dns_header.hpp src/dns_header.cpp src/dns_packet.hpp src/dns_packet.cpp src/dns_question.hpp src/dns_question.cpp src/in_cksum.hpp src/in_cksum.cpp src/rr.hpp src/rr.cpp src/tokenizer.hpp src/tokenizer.cpp version.hpp src/main.cpp src/convert.cpp src/convert.hpp src/server.hpp src/server.cpp
dines_CXXFLAGS = -Wall -Werror -std=c++0x -Isrc
test_dines_SOURCES = src/debug.hpp src/dns_header.hpp src/dns_header.cpp src/dns_packet.hpp src/dns_packet.cpp src/dns_question.hpp src/dns_question.cpp src/in_cksum.hpp src/in_cksum.cpp src/rr.hpp src/rr.cpp src/tokenizer.hpp src/tokenizer.cpp version.hpp src/convert.cpp src/convert.hpp test/test.cpp
test_dines_CXXFLAGS = -Wall -std=c++0x -Isrc -Itest
test: test_dines
	./test_dines
