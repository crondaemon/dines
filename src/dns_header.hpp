#ifndef __DNSHEADER_HPP__
#define __DNSHEADER_HPP__

#include <stdint.h>
#include <string>
#include <dinestypes.hpp>

#pragma pack(1)
typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
    union {
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

bool operator==(const DnsHeaderFlags& f1, const DnsHeaderFlags& f2);
bool operator!=(const DnsHeaderFlags& f1, const DnsHeaderFlags& f2);

class DnsHeader {
    uint16_t _txid;
    DnsHeaderFlags _flags;
    uint16_t _nRecord[4];
    bool _fuzzFlags;
    bool _fuzzTxid;
    bool _fuzzNRecord[4];

    void _checkSection(unsigned section) const;

public:
    DnsHeader(const uint16_t txid = 0, const uint32_t nquest = 0, const uint32_t nans = 0,
        const uint32_t nadd = 0, const uint32_t nauth = 0);
    DnsHeader(const DnsHeader& h);

    DnsHeader& operator=(const DnsHeader& h);

    void nRecord(unsigned section, uint16_t value);

    uint16_t nRecord(unsigned section) const;

    void nRecordAdd(unsigned section, unsigned n);

    uint16_t txid() const;
    void txid(uint16_t txid);

    bool rd() const;
    void rd(bool rec_des);

    bool ra() const;
    void ra(bool rec_avail);

    DnsHeaderFlags flags() const;

    std::string data() const;

    bool isQuestion() const;
    void isQuestion(bool isQuestion);

    bool isRecursive() const;
    void isRecursive(bool isRecursive);

    void fuzz();

    void fuzzFlags();
    void fuzzTxid();
    void fuzzNRecord(unsigned section);

    void parse(char* buf);
};

#endif 