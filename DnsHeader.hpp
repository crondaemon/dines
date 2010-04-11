
#ifndef __DNSHEADER_HPP__
#define __DNSHEADER_HPP__

#include <cstdint>

typedef enum {
    R_QUESTION,
    R_ANSWER,
    R_ADDITIONAL,
    R_AUTHORITATIVE
} RecordType;

class DnsHeader {
    uint16_t _txid;

    uint32_t _nquest;
    uint32_t _nans;
    uint32_t _nadd;
    uint32_t _nauth;
    
public:
    DnsHeader() : _txid(0), _nquest(0), _nans(0), _nadd(0), _nauth(0) {}
    DnsHeader(const uint16_t txid, const uint32_t nquest, const uint32_t nans,
        const uint32_t nadd, const uint32_t nauth) :
        _txid(txid),
        _nquest(nquest),
        _nans(nans),
        _nauth(nauth)
        {}
        
    uint16_t txid() const { return _txid; }
    
    void txid(const uint16_t txid) { _txid = txid; }
        
    void RecordSet(const RecordType rt, uint32_t value);
    
    void RecordGet(const RecordType rt) const;
    
    void RecordInc(const RecordType rt);
    
    void RecordDec(const RecordType rt);
};

#endif 
