
#ifndef __DNSDOMAIN_HPP__
#define __DNSDOMAIN_HPP__

#include <vector>
#include <string>

class DnsDomain {
    std::vector<std::string> frags;
public:
    DnsDomain();
    DnsDomain(const std::string domain);
    
    std::string data() const;
};

#endif
