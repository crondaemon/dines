
#include "dns_domain.hpp"

#include "tokenizer.hpp"

#include <iostream>

using namespace std;

DnsDomain::DnsDomain(const string& domain)
{
    cout << "ELEMENTI " << _frags.size() << endl;
    _frags.clear();
    _frags = tokenize(domain, ".");
    cout << "DNSDOMAIN " << this << " " << domain << " con " << _frags.size() << endl;
}

DnsDomain::DnsDomain(const DnsDomain& domain)
{
    cout << "DNSDOMAIN copy costructor" << endl;
    _frags.clear();
    *this = domain;
}

DnsDomain& DnsDomain::operator=(const DnsDomain& domain)
{
    _frags.clear();
    cout << __func__ << "dnsdomain start" << endl;
    for (vector<string>::const_iterator i = domain._frags.begin(); i != domain._frags.end(); i++) {
        cout << "Processo " << *i << endl;
        _frags.push_back(*i);
    }
    cout << __func__ << "dnsdomain end" << endl;
    return *this;
}

string DnsDomain::data() const
{
    string out = "";
    cout << "DNSDOMAIN data on " << this << endl;
    cout << "INVOKE DATA " << _frags.size() << " 1=" << _frags.at(0) << endl;
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

