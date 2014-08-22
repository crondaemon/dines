
#include "tokenizer.hpp"

std::vector<std::string> tokenize(const std::string& str, const std::string& sep)
{
    std::vector<std::string> result;

    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(sep, 0);
    // Find first "non-delimiter".
    std::string::size_type pos = str.find_first_of(sep, lastPos);

    while (std::string::npos != pos || std::string::npos != lastPos) {
        // Found a token, add it to the vector.
        result.push_back(str.substr(lastPos, pos - lastPos));
        
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(sep, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(sep, lastPos);
    }
    
    return result;
}

