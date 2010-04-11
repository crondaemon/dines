CC=g++

CFLAGS=-c -Wall -std=c++0x 

LDFLAGS=

SOURCES=main.cpp DnsPacket.cpp DnsHeader.cpp

OBJECTS=$(SOURCES:.cpp=.o)

EXECUTABLE=dines

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o dines
	
