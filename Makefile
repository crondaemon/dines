CC=g++

CFLAGS=-c -Wall -std=c++0x

LDFLAGS=

SOURCES=\
    main.cpp \
    dns_packet.cpp \
    dns_header.cpp \
    dns_question.cpp \
    dns_domain.cpp \
    fuzzer.cpp

EXECUTABLE=dines

OBJECTS=$(SOURCES:.cpp=.o)

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -g -c $<

clean:
	rm -rf *.o dines core.*
	
