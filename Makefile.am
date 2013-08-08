bin_PROGRAMS = dines test_dines
dines_SOURCES = debug.hpp dns_header.hpp dns_packet.hpp dns_question.hpp in_cksum.hpp rr.hpp tokenizer.hpp version.hpp dns_header.cpp dns_packet.cpp dns_question.cpp in_cksum.cpp main.cpp rr.cpp tokenizer.cpp convert.cpp
dines_CXXFLAGS = -Wall
test_dines_SOURCES = debug.hpp dns_header.hpp dns_packet.hpp dns_question.hpp in_cksum.hpp rr.hpp tokenizer.hpp version.hpp dns_header.cpp dns_packet.cpp dns_question.cpp in_cksum.cpp test.cpp rr.cpp tokenizer.cpp convert.cpp convert.hpp
test_dines_CXXFLAGS = -Wall
test: test_dines
	./test_dines
