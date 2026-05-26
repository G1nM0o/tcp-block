#pragma once

#include <cstdint>

#pragma pack(push, 1)

struct EthHdr {
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
};

#pragma pack(pop)

constexpr uint16_t ETH_TYPE_IP = 0x0800;