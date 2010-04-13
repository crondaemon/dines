
#include "DnsDomain.hpp"

using namespace std;

DnsDomain::DnsDomain()
{
    frags.clear();
}

DnsDomain::DnsDomain(const string domain)
{
    frags.clear();

    // We have to tokenize
    
    // Skip delimiters at beginning.
    string::size_type lastPos = domain.find_first_not_of(".", 0);
    // Find first "non-delimiter".
    string::size_type pos     = domain.find_first_of(".", lastPos);

    while (string::npos != pos || string::npos != lastPos)
    {
        // Found a token, add it to the vector.
        frags.push_back(domain.substr(lastPos, pos - lastPos));
        
        // Skip delimiters.  Note the "not_of"
        lastPos = domain.find_first_not_of(".", pos);
        // Find next "non-delimiter"
        pos = domain.find_first_of(".", lastPos);
    }
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
    
    return out;
}

