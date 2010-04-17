
#ifndef __DNSDOMAIN_HPP__
#define __DNSDOMAIN_HPP__

#include <vector>
#include <string>

class DnsDomain {
    std::vector<std::string> frags;
public:
    DnsDomain(const std::string domain = "");
    
    //DnsDomain(const char* domain);
    
    std::string data() const;
    
    std::string str() const;
};

#endif
