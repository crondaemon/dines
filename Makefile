CC=g++

CFLAGS=-c -Wall -std=c++0x 

LDFLAGS=

SOURCES=\
    main.cpp \
    DnsPacket.cpp \
    DnsHeader.cpp \
    DnsQuestion.cpp \
    DnsDomain.cpp

EXECUTABLE=dines

OBJECTS=$(SOURCES:.cpp=.o)

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o dines
	
