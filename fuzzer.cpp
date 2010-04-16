
#include "fuzzer.hpp"

#include <iostream>
#include <stdexcept>
#include <time.h>

using namespace std;

Fuzzer::Fuzzer()
{
    srand(time(NULL));
}

void Fuzzer::addAddress(void* addr, unsigned len)
{
    cout << "Adding address " << addr << " len " << len << " to fuzzer.\n";
    _addrs.push_back(make_pair(addr, len));
}

void Fuzzer::goFuzz()
{
    for (vector<FuzzAddress>::iterator itr = _addrs.begin(); itr != _addrs.end(); ++itr) {
        for (unsigned i = 0; i < itr->second; i++) {
            ((char*)itr->first)[i] = rand() % 255;
        }
    }
}

