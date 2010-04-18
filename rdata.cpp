
#include "rdata.hpp"

#include <stdexcept>
#include <sstream>

using namespace std;

string Rdata::data() const
{
    string out = "";
    
    return out;
}

Rdata::Rdata(const std::string dom, const unsigned type)
{
    switch(type) {
        case 1:
        break;
        
        default:
            stringstream ss;
            ss << "Type ";
            ss << type;
            ss << " not supported.";
            throw runtime_error(ss.str());
    }
}
