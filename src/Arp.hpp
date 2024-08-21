#pragma once

#include <Headers.hpp>
#include <Types.hpp>

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

struct ArpIpBody
{
    MacAddress mSourceMacAddress;
    IpAddress mSourceIp;
    MacAddress mDestinationMacAddress;
    IpAddress mDestinationIp;
} __attribute__((packed));
static_assert(sizeof(ArpIpBody) == 20, "Arp IP body must be 20 bytes long");

template <>
struct LayoutInfo<ArpIpBody>
{
    static constexpr std::index_sequence<6, 4, 6, 4> Sizes{};
};

template <> struct std::formatter<ArpIpBody> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const ArpIpBody& body, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "ARP IP body: MAC {} -> {} to IP {} -> {}",
            body.mSourceMacAddress, body.mDestinationMacAddress, body.mSourceIp, body.mDestinationIp);
    }
};
