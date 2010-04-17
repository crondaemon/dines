
#include "dns_domain.hpp"

#include "tokenizer.hpp"

using namespace std;

DnsDomain::DnsDomain(const string domain)
{
    frags.clear();
    frags = tokenize(domain, ".");
}

string DnsDomain::data() const
{
    string out = "";
    
    for (vector<string>::const_iterator itr = frags.begin(); itr != frags.end(); ++itr) {
        // Add the len
        out.append(1, itr->length());
        // Add the frag
        out.append(*itr);
    }
    out.append(1, 0);
    
    return out;
}

string DnsDomain::str() const 
{
    string out = "";
    for (vector<string>::const_iterator itr = frags.begin(); itr != frags.end(); ++itr) {
        out += *itr;
        out += ".";
    }
    return out.substr(0,out.length()-1);
}

