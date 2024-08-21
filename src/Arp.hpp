#pragma once

#include <Headers.hpp>

#include <cstddef>
#include <cstdint>

struct ArpHeader
{
    std::uint16_t mHardwareType;
    std::uint16_t mProtocolType;
    std::uint8_t mHardwareSize;
    std::uint8_t mProtocolSize;
    std::uint16_t mOpCode;
};
static_assert(sizeof(ArpHeader) == 8, "Arp header must be 8 bytes long");

template <>
struct LayoutInfo<ArpHeader>
{
    static constexpr std::index_sequence<2, 2, 1, 1, 2> Sizes{};
};
