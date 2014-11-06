cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project("Dines")

set(Dines_VERSION_MAJOR 0)
set(Dines_VERSION_MINOR 1)

enable_testing()

add_executable(dines
src/dns_header.cpp
src/dns_packet.cpp
src/dns_question.cpp
src/main.cpp
src/rr.cpp
src/server.cpp
src/tokenizer.cpp
src/utils.cpp)

add_executable(test_dines
src/server.hpp
src/server.cpp
src/debug.hpp
src/dns_header.hpp
src/dns_header.cpp
src/dns_packet.hpp
src/dns_packet.cpp
src/dns_question.hpp
src/dns_question.cpp
src/rr.hpp
src/rr.cpp
src/tokenizer.hpp
src/tokenizer.cpp
src/utils.cpp
src/utils.hpp
tests/test_base.cpp
tests/test.hpp)


add_executable(test_root_dines
src/server.hpp
src/server.cpp
src/debug.hpp
src/dns_header.hpp
src/dns_header.cpp
src/dns_packet.hpp
src/dns_packet.cpp
src/dns_question.hpp
src/dns_question.cpp
src/rr.hpp
src/rr.cpp
src/tokenizer.hpp
src/tokenizer.cpp
src/utils.cpp
src/utils.hpp
tests/test_root.cpp
tests/test.hpp)

include_directories(src)
include_directories(.)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(tests)

set(CMAKE_CXX_FLAGS "-g -Wall -Werror -std=c++11")

target_link_libraries(dines resolv)
target_link_libraries(test_dines cppunit resolv pthread)
target_link_libraries(test_root_dines cppunit resolv pthread)

add_test(unit test_dines)
add_test(readme ../tests/readme_check.sh)
add_test(root sudo ./test_root_dines)
add_test(live ../tests/live_tests.sh)

# Store the git hash of the current head
if(EXISTS "${PROJECT_SOURCE_DIR}/.git/HEAD")
    execute_process(COMMAND git describe
        OUTPUT_VARIABLE DINES_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    execute_process(COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/src/VERSION
        OUTPUT_VARIABLE DINES_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
