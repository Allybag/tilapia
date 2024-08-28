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
    // TODO: We don't actually have to convert to network byte order,
    // as one's complement addition is commuative
    // we just have to assemble the right 16 bit words
    //
    // For example, for a struct A with layout
    // { 1 byte, 1 byte, 2 bytes, 4 bytes };
    // If we read from the network:
    // 0x12 0x34 0x56 0x78 0xAA 0xBB 0xCC 0xDD
    // we byteswap to ->
    // 0x12 0x34 0x78 0x56 0xDD 0xCC 0xBB 0xAA
    //
    // We don't need to swap all the way back to network byte order,
    // we just need to be consistent one way or the other
    // In the case above, and in an IPv4 header,
    // we could just byteswap the first 16 bit word
    // and then we would consistently be in host byte order
    // We would then not byteswap the final result
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
        std::println("result 0x{:x}, sum 0x{:x}, word 0x{:x}", result, sum, word);
    }

    // Then we negate and then byteswap the result back into host byte order
    result = ~result;
    result = std::byteswap(result);
    std::println("Result: 0x{:x}, checksum: 0x{:x}", result, header.checksum());
    return result;
}

uint32_t sum_every_16bits(void *addr, int count)
{
    uint32_t sum = 0;
    uint16_t * ptr = reinterpret_cast<uint16_t*>(addr);
    
    while( count > 1 )  {
        /*  This is the inner loop */
        std::println("Sami style: prior sum 0x{:x}, word 0x{:x}", sum, *ptr); 
        sum += * ptr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (uint8_t *) ptr;

    return sum;
}

uint16_t checksum(void *addr, int count, int start_sum)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     * Taken from https://tools.ietf.org/html/rfc1071
     */
    uint32_t sum = start_sum;

    std::println("Sami style: start sum 0x{:x}", sum);
    sum += sum_every_16bits(addr, count);
    std::println("Sami style: end sum 0x{:x}", sum);
    
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
    {
        std::println("Sami style: pre fold 0x{:x}", sum);
        sum = (sum & 0xffff) + (sum >> 16);
        std::println("Sami style: post fold 0x{:x}", sum);
    }

    std::println("Sami style: pre negate 0x{:x}", sum);
    return ~sum;
}

int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;


    std::println("Sami style: inital sum 0x{:x}", sum);
    sum += saddr;
    std::println("Sami style: post saddr 0x{:x}, 0x{:x}", sum, saddr);
    sum += daddr;
    std::println("Sami style: post daddr 0x{:x}, 0x{:x}", sum, daddr);
    sum += htons(proto);
    std::println("Sami style: post proto 0x{:x}, 0x{:x}", sum, htons(proto));
    sum += htons(len);
    std::println("Sami style: post len 0x{:x}, 0x{:x}", sum, htons(len));
    
    return checksum(data, len, sum);
}

int tcp_v4_checksum(uint8_t* data, uint32_t len, uint32_t saddr, uint32_t daddr)
{
    return tcp_udp_checksum(saddr, daddr, std::to_underlying(IPProtocol::TCP), data, len);
}
