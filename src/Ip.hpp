#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>
#include <bit>

struct VersionLength
{
    // These are defined as version then length,
    // but because of endianness we reverse them here
    std::uint8_t mLength: 4;
    std::uint8_t mVersion: 4;
};

struct FlagsOffset
{
    // As above, reversed
    std::uint16_t mFragOffset: 13; // Position of this fragment in datagram
    std::uint16_t mFlags: 3;
};

struct IpV4Header
{
    VersionLength mVersionLength;
    std::uint8_t mTypeOfService;
    std::uint16_t mTotalLength; // Includes header and data
    std::uint16_t mId; // A counter for reassembling IP datagrams
    FlagsOffset mFlagsOffset;
    std::uint8_t mTimeToLive;
    std::uint8_t mProto;
    std::uint16_t mCheckSum;
    IpAddress mSourceAddress;
    IpAddress mDestinationAddress;
};
static_assert(sizeof(IpV4Header) == 20, "IP header must be 20 bytes long");

template <>
struct LayoutInfo<IpV4Header>
{
    static constexpr std::index_sequence<1, 1, 2, 2, 2, 1, 1, 2, 4, 4> Sizes{};
};

template <> struct std::formatter<IpV4Header> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IpV4Header& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "IP Header of size {}: {} -> {}", header.mTotalLength, header.mSourceAddress, header.mDestinationAddress);
    }
};

inline std::uint16_t checksum(const IpV4Header& ip)
{
    std::uint16_t result{};

    static constexpr auto cWordsInIp = sizeof(ip) / sizeof(std::uint16_t);
    static_assert(cWordsInIp == 10);
    const auto words = std::bit_cast<std::array<const std::uint16_t, cWordsInIp>>(ip);

    for (const auto word : words)
    {
        auto num = std::byteswap(word);
        std::uint32_t sum = result + num;
        result = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~result;
}
