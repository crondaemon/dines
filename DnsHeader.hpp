
#ifndef __DNSHEADER_HPP__
#define __DNSHEADER_HPP__

#include <cstdint>
#include <string>

#pragma pack(1)
typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t qr: 1,
            opcode: 4,
            aa: 1,
            tc: 1,
            rd: 1;
    uint8_t ra: 1,
            z: 1,
            auth: 1,
            cd: 1,
            rcode: 4;
#else
    uint8_t rd: 1,
            tc: 1,
            aa: 1,
            opcode: 4,
            qr: 1;
    uint8_t rcode: 4,
            cd: 1,
            auth: 1,
            z: 1,
            ra: 1;
#endif
} DnsHeaderFlags;

class DnsHeader {
public:

    typedef enum {
        R_QUESTION = 0,
        R_ANSWER,
        R_ADDITIONAL,
        R_AUTHORITATIVE
    } RecordType;

    uint16_t txid;

    DnsHeaderFlags flags;

    uint32_t nrecord[4];
    
    DnsHeader();
    DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth);
        
    void RecordSet(const RecordType rt, const uint32_t value);
    
    uint32_t RecordGet(const RecordType rt) const;
    
    void RecordInc(const RecordType rt);
    
    void RecordDec(const RecordType rt);
    
    std::string data() const;
private:
    void RecordAdd(const RecordType rt, const int value);
};

#endif 
