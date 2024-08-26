#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>
#include <bit>

enum class IPProtocol : std::uint8_t
{
    ICMP = 1, // Intenet Control Message Protocol
    IGMP = 2, // Internet Group Management Protocol
    TCP = 6,  // Transmission Control Protocol
    UDP = 17, // User Datagram Protocol
};

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
    IPProtocol mProto;
    std::uint16_t mCheckSum;
    IpAddress mSourceAddress;
    IpAddress mDestinationAddress;

    void zero_out_checksum()
    {
        mCheckSum = 0;
    }

    auto checksum() const
    {
        return mCheckSum;
    }
};
static_assert(sizeof(IpV4Header) == 20, "IP header must be 20 bytes long");

template <>
struct LayoutInfo<IpV4Header>
{
    static constexpr std::index_sequence<1, 1, 2, 2, 2, 1, 1, 2, 4, 4> Sizes{};
};

template <> struct std::formatter<IPProtocol> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IPProtocol& ipProto, FormatContext& ctx) const
    {
        using enum IPProtocol;
        switch (ipProto)
        {
        case IPProtocol::ICMP:
            return std::format_to(ctx.out(), "ICMP");
        case IPProtocol::IGMP:
            return std::format_to(ctx.out(), "IGMP");
        case IPProtocol::TCP:
            return std::format_to(ctx.out(), "TCP");
        case IPProtocol::UDP:
            return std::format_to(ctx.out(), "UDP");
        default:
            throw std::runtime_error{std::format("Unexpected IP Protocol Type: {}", std::to_underlying(ipProto))};
        }
    }
};


template <> struct std::formatter<IpV4Header> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IpV4Header& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "IP Header of type {}, size {}: {} -> {}",
            header.mProto, header.mTotalLength, header.mSourceAddress, header.mDestinationAddress);
    }
};

template <typename HeaderT>
inline std::uint16_t checksum(const HeaderT& header)
{
    // First we remove the checksum
    auto header_no_checksum{header};
    header_no_checksum.zero_out_checksum();

    // Then we convert back to network byte order
    std::array<std::byte, sizeof(HeaderT)> bytes;
    std::memcpy(&bytes, &header_no_checksum, sizeof(header));
    byteswapMembers(bytes, LayoutInfo<HeaderT>::Sizes);

    // Then convert to an array of 16 bit words
    static constexpr auto cWordsInHeader = sizeof(header) / sizeof(std::uint16_t);
    const auto words = std::bit_cast<std::array<const std::uint16_t, cWordsInHeader>>(bytes);

    // Then we do a cumulative one's complement 16 bit sum over each word
    std::uint16_t result{};
    for (const auto word : words)
    {
        std::uint32_t sum = result + word;
        result = (sum & 0xFFFF) + (sum >> 16);
    }

    // Then we negate and then byteswap the result back into host byte order
    result = ~result;
    result = std::byteswap(result);
    std::println("Result: 0x{:x}, checksum: 0x{:x}", result, header.checksum());
    return result;
}
