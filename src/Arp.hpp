#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>

using ArpProtoType = EtherType; // These are a subset apparently

enum class ArpHardwareType : std::uint16_t
{
    Ethernet = 1
};

template <> struct std::formatter<ArpHardwareType> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const ArpHardwareType& hardwareType, FormatContext& ctx) const
    {
        using enum ArpHardwareType;
        switch (hardwareType)
        {
        case ArpHardwareType::Ethernet:
            return std::format_to(ctx.out(), "Ethernet");
        default:
            throw std::runtime_error{std::format("Unexpected ARP Hardware Type: {}", std::to_underlying(hardwareType))};
        }
    }
};

enum class ArpOpCode : std::uint16_t
{
    Request = 1,
    Reply = 2,
};

template <> struct std::formatter<ArpOpCode> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const ArpOpCode& opCode, FormatContext& ctx) const
    {
        using enum ArpOpCode;
        switch (opCode)
        {
        case ArpOpCode::Request:
            return std::format_to(ctx.out(), "Request");
        case ArpOpCode::Reply:
            return std::format_to(ctx.out(), "Reply");
        default:
            throw std::runtime_error{std::format("Unexpected ARP OpCode: {}", std::to_underlying(opCode))};
        }
    }
};

struct ArpHeader
{
    ArpHardwareType mHardwareType;
    ArpProtoType mProtocolType;
    std::uint8_t mHardwareSize;
    std::uint8_t mProtocolSize;
    ArpOpCode mOpCode;
};
static_assert(sizeof(ArpHeader) == 8, "Arp header must be 8 bytes long");

template <>
struct LayoutInfo<ArpHeader>
{
    static constexpr std::index_sequence<2, 2, 1, 1, 2> Sizes{};
};

template <> struct std::formatter<ArpHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const ArpHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "ARP Header: Protocol {}, Operation {}", header.mProtocolType, header.mOpCode);
    }
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
