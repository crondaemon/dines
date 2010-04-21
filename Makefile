CC=g++

CFLAGS=-c -Wall -std=c++0x

LDFLAGS=

SOURCES=\
    main.cpp \
    dns_packet.cpp \
    dns_header.cpp \
    dns_question.cpp \
    fuzzer.cpp \
    tokenizer.cpp \
    rr.cpp

EXECUTABLE=dines

OBJECTS=$(SOURCES:.cpp=.o)

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -g -c $<

clean:
	@rm -rf *.o dines core.*
	
VERSION=`cat version.hpp | cut -d ' ' -f 3`
	
tar:
	@mkdir dines-$(VERSION)
	@cp *.cpp *.hpp dines-$(VERSION)
	@cp Makefile dines-$(VERSION)
	@tar czf dines-$(VERSION).tar.gz dines-$(VERSION)
	@rm -rf dines-$(VERSION)

