#pragma once

#include <cstdint>

#pragma pack(push, 1)

struct IpHdr {
    uint8_t  vhl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t sum;
    uint32_t sip;
    uint32_t dip;
};

#pragma pack(pop)

constexpr uint8_t IP_PROTO_TCP = 6;