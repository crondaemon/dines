
#include "fuzzer.hpp"

#include <iostream>
#include <stdexcept>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

using namespace std;

Fuzzer::Fuzzer()
{
    srand(time(NULL));
}

void Fuzzer::addAddress(const void* addr, const unsigned len)
{
    cout << "Adding address " << addr << " len=" << len << " to fuzzer.\n";
    _addrs[const_cast<void*>(addr)] = len;
}

void Fuzzer::delAddress(const void* addr)
{
    _addrs.erase(_addrs.find(const_cast<void*>(addr)));
}

void Fuzzer::goFuzz()
{
    for (map<void*,unsigned>::iterator itr = _addrs.begin(); itr != _addrs.end(); ++itr) {
        for (unsigned i = 0; i < itr->second; i++) {
            ((char*)itr->first)[i] = rand() % 255;
        }
    }
}

bool Fuzzer::hasAddress(const void* addr)
{
    if (_addrs.find(const_cast<void*>(addr)) != _addrs.end())
        return true;

    return false;
}

Fuzzer::~Fuzzer()
{
//    cout << "distruggo fuzzer " << _addrs.size() << endl;
    _addrs.~map<void*,unsigned>();

}
