
#ifndef __DNSHEADER_HPP__
#define __DNSHEADER_HPP__

#include <cstdint>
#include <string>

typedef enum {
    R_QUESTION,
    R_ANSWER,
    R_ADDITIONAL,
    R_AUTHORITATIVE
} RecordType;

typedef struct {
    uint32_t
        qr:1,
        opcode:4,
        aa:1,
        tc:1,
        rd:1,
        ra:1,
        z:1,
        ad:1,
        cd:1,
        rcode:4;
} DnsHeaderFlags;

class DnsHeader {
    uint16_t _txid;

    DnsHeaderFlags flags;

    uint32_t _nrecord[4];
    
    void RecordAdd(const RecordType rt, const int value);

public:
    DnsHeader();
    DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth);
        
    uint16_t txid() const { return _txid; }
    
    void txid(const uint16_t txid) { _txid = txid; }
        
    void RecordSet(const RecordType rt, const uint32_t value);
    
    uint32_t RecordGet(const RecordType rt) const;
    
    void RecordInc(const RecordType rt);
    
    void RecordDec(const RecordType rt);
    
    std::string data() const;
};

#endif 
