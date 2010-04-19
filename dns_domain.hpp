
#ifndef __DNSDOMAIN_HPP__
#define __DNSDOMAIN_HPP__

#include <vector>
#include <string>

class DnsDomain {
    std::vector<std::string> _frags;
public:
    DnsDomain(const std::string& domain = "");
    
    DnsDomain(const DnsDomain& domain);
    
    std::string data() const;
    
    std::string str() const;
    
    unsigned nfrags() const { return _frags.size(); }
    
    DnsDomain& operator=(const DnsDomain& domain);
};

#endif
