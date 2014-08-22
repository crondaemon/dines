
#ifndef __DINESTYPES_HPP__
#define __DINESTYPES_HPP__

namespace Dines {

typedef enum {
    R_QUESTION = 0,
    R_ANSWER = 1,
    R_ADDITIONAL = 2,
    R_AUTHORITIES = 3
} RecordSection;

typedef void (*LogFunc)(std::string);

};

#endif
