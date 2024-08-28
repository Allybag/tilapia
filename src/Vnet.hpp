#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstdint>
#include <cstring>
#include <format>
#include <print>
#include <utility>

enum class VnetFlag : std::uint8_t
{
    None = 0,
    NeedsChecksum = 1,
    ChecksumValid = 2,
};

enum class GenericSegmentOffloadType : std::uint8_t
{
    None = 0,
    TcpIp4 = 1,
    Udp = 2,
    TcpIp6 = 4,
    UdpL4 = 5,
    TcpEcn = 0x80,
};

// We can use this header to offload checksum calculations
// The hardware or kernel will compute the internet checksum
// from mChecksumStart bytes after the start of the Etherner frame
// to the end of the packet, and store the result mChecksumOffset
// bytes after mChecksumStart
// For TCP we should set the checksum to be the psuedoheader checksum
// before sending the frame.
struct VnetHeader
{
    VnetFlag mFlag;
    GenericSegmentOffloadType mGsoType;
    std::uint16_t mHeaderLength; // Length of Ethernet + IP + TCP/UDP headers 
    std::uint16_t mGsoSize; // I think this should be segment size?
    std::uint16_t mChecksumStart; // How many bytes of Ethernet/IP/non checksummable headers
    std::uint16_t mChecksumOffset; // How many bytes from mCheckSumStart is the checksum stored 
    std::uint16_t mNumBuffers; // Apparently this is used for coalesced buffers, always set to 1
};
static_assert(sizeof(VnetHeader) == 12, "Vnet header must be 14 bytes long");

template <>
struct LayoutInfo<VnetHeader>
{
    // This is not a network header, so should not be byteswapped
    static constexpr std::index_sequence<0> Sizes{};
};

template <> struct std::formatter<VnetFlag> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const VnetFlag& vnetFlag, FormatContext& ctx) const
    {
        switch (vnetFlag)
        {
        case VnetFlag::None:
            return std::format_to(ctx.out(), "None");
        case VnetFlag::ChecksumValid:
            return std::format_to(ctx.out(), "ChecksumValid");
        case VnetFlag::NeedsChecksum:
            return std::format_to(ctx.out(), "NeedsChecksum");
        default:
            throw std::runtime_error{std::format("Unexpected VNET Flag: {}", std::to_underlying(vnetFlag))};
        }
    }
};

template <> struct std::formatter<GenericSegmentOffloadType> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const GenericSegmentOffloadType& gsoType, FormatContext& ctx) const
    {
        switch (gsoType)
        {
        case GenericSegmentOffloadType::None:
            return std::format_to(ctx.out(), "None");
        case GenericSegmentOffloadType::TcpIp4:
            return std::format_to(ctx.out(), "TcpIp4");
        case GenericSegmentOffloadType::Udp:
            return std::format_to(ctx.out(), "Udp");
        case GenericSegmentOffloadType::TcpIp6:
            return std::format_to(ctx.out(), "TcpIp6");
        case GenericSegmentOffloadType::TcpEcn:
            return std::format_to(ctx.out(), "TcpEcn");
        case GenericSegmentOffloadType::UdpL4:
            return std::format_to(ctx.out(), "UdpL4");
        default:
            throw std::runtime_error{std::format("Unexpected GSO type: {}", std::to_underlying(gsoType))};
        }
    }
};

template <> struct std::formatter<VnetHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const VnetHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "Virtual Network Header: {}, {}", header.mFlag, header.mGsoType);
    }
};
