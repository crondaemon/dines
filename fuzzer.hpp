
#ifndef __FUZZER_HPP__
#define __FUZZER_HPP__

//#include <pair>
#include <vector>

typedef std::pair<void*, unsigned> FuzzAddress;

class Fuzzer {
    std::vector<FuzzAddress> _addrs;
    int _random;
public:
    Fuzzer();
    void addAddress(void* addr, unsigned len);
    void goFuzz();
};

#endif 
