bin_PROGRAMS = dines test_dines test_root_dines
AUTOMAKE_OPTIONS = subdir-objects

CXXFLAGS += -Wall -Werror -std=c++11 -Isrc
CXXFLAGS += `if [ "$$TRAVIS" != "" ]; then echo "-DTRAVIS"; fi`

dines_SOURCES = src/debug.hpp src/dns_header.hpp src/dns_header.cpp src/dns_packet.hpp src/dns_packet.cpp src/dns_question.hpp src/dns_question.cpp src/rr.hpp src/rr.cpp src/tokenizer.hpp src/tokenizer.cpp version.hpp src/main.cpp src/utils.cpp src/utils.hpp src/server.hpp src/server.cpp
dines_CXXFLAGS =
dines_LDADD = -lresolv

test_dines_SOURCES = src/server.hpp src/server.cpp src/debug.hpp src/dns_header.hpp src/dns_header.cpp src/dns_packet.hpp src/dns_packet.cpp src/dns_question.hpp src/dns_question.cpp src/rr.hpp src/rr.cpp src/tokenizer.hpp src/tokenizer.cpp version.hpp src/utils.cpp src/utils.hpp tests/test_base.cpp tests/test.hpp
test_dines_CXXFLAGS = -Itests
test_dines_LDADD = -lresolv -lpthread -lcppunit

test_root_dines_SOURCES = src/server.hpp src/server.cpp src/debug.hpp src/dns_header.hpp src/dns_header.cpp src/dns_packet.hpp src/dns_packet.cpp src/dns_question.hpp src/dns_question.cpp src/rr.hpp src/rr.cpp src/tokenizer.hpp src/tokenizer.cpp version.hpp src/utils.cpp src/utils.hpp tests/test_root.cpp tests/test.hpp
test_root_dines_CXXFLAGS = -Itests
test_root_dines_LDADD = -lresolv -lpthread -lcppunit

tests: test_dines test_root_dines
	./tests/readme_check.sh && ./test_dines && sudo ./test_root_dines && ./tests/live_tests.sh
clean-local:
	for dir in . src tests; do rm -rf $$dir/*~ $$dir/*.csmes $$dir/*.csexe $$dir/*.gcno $$dir/*.gcda $$dir/*.gcov; done;
