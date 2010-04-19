
#include "dns_domain.hpp"

#include "tokenizer.hpp"

#include <iostream>

using namespace std;

DnsDomain::DnsDomain(const string& domain)
{
    _frags.clear();
    _frags = tokenize(domain, ".");
}

DnsDomain::DnsDomain(const DnsDomain& domain)
{
    *this = domain;
}

DnsDomain& DnsDomain::operator=(const DnsDomain& domain)
{
    //cout << "DnsDomain " <<  __func__ << &domain << endl;
    //cout << " ci sono " << domain._frags.size() << endl;
    //for (vector<string>::const_iterator itr = domain._frags.begin(); itr != domain._frags.end(); ++itr) {
        //cout << "ROUND " << *itr << endl;
    //    _frags.push_back(*itr);
    //}
    _frags = domain._frags;
    return *this;
}

string DnsDomain::data() const
{
    string out = "";
    
    for (vector<string>::const_iterator itr = _frags.begin(); itr != _frags.end(); ++itr) {
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
    for (vector<string>::const_iterator itr = _frags.begin(); itr != _frags.end(); ++itr) {
        out += *itr;
        out += ".";
    }
    return out.substr(0, out.length()-1);
}

