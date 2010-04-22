
#ifndef __FUZZER_HPP__
#define __FUZZER_HPP__

#include <map>
#include <vector>

class Fuzzer {
    std::map<void*,unsigned> _addrs;
    int _random;
public:
    Fuzzer();
    void addAddress(const void* addr, const unsigned len);
    void delAddress(const void* addr);
    bool hasAddress(const void* addr);
    void goFuzz();
    
    ~Fuzzer();
};

#endif 
