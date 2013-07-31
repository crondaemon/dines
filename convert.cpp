
#include <convert.hpp>

#include <vector>
#include <tokenizer.hpp>

std::string convertDomain(const std::string& s)
{
    std::string out = "";
    std::vector<std::string> frags = tokenize(s, ".");

    for (std::vector<std::string>::const_iterator itr = frags.begin(); itr != frags.end(); ++itr) {
        // Add the len
        out.append(1, itr->length());
        // Add the frag
        out.append(*itr);
    }
    out.append(1, 0);

    return out;
}
