#pragma once

#include <cstdint>

#pragma pack(push, 1)

struct TcpHdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off;
    uint8_t  flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

#pragma pack(pop)

constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_ACK = 0x10;
