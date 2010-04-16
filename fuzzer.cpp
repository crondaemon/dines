
#include "fuzzer.hpp"

#include <iostream>
#include <stdexcept>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
       
using namespace std;

Fuzzer::Fuzzer()
{
    srand(time(NULL));
    
    _random = open("/dev/urandom", O_RDONLY);
    if (_random < 0)
        throw runtime_error("Unable to open /dev/random");
}

void Fuzzer::addAddress(void* addr, unsigned len)
{
    cout << "Adding address " << addr << " len " << len << " to fuzzer.\n";
    _addrs.push_back(make_pair(addr, len));
}

void Fuzzer::goFuzz()
{
    //char c = 7;
    //char cc = 8;
    for (vector<FuzzAddress>::iterator itr = _addrs.begin(); itr != _addrs.end(); ++itr) {
        for (unsigned i = 0; i < itr->second; i++) {
            //read(_random, &c, 1);
            ((char*)itr->first)[i] = rand() % 255;
        }
        //read(_random, itr->first, itr->second);
    }
}

