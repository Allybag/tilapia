#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>

enum class IcmpType : std::uint8_t
{
    EchoReply = 0,
    DestinationUnreachable = 3,
    EchoRequest = 8,
};

struct IcmpV4Header
{
    IcmpType mType;
    std::uint8_t mCode;
    std::uint16_t mCheckSum;
};

template <>
struct LayoutInfo<IcmpV4Header>
{
    static constexpr std::index_sequence<1, 1, 2> Sizes{};
};

struct IcmpV4Echo
{
    std::uint16_t mId;
    std::uint16_t mSeq;
};

template <>
struct LayoutInfo<IcmpV4Echo>
{
    static constexpr std::index_sequence<2, 2> Sizes{};
};

template <> struct std::formatter<IcmpType> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IcmpType& icmpType, FormatContext& ctx) const
    {
        using enum IcmpType;
        switch (icmpType)
        {
        case IcmpType::EchoRequest:
            return std::format_to(ctx.out(), "Echo Request");
        case IcmpType::EchoReply:
            return std::format_to(ctx.out(), "Echo Reply");
        case IcmpType::DestinationUnreachable:
            return std::format_to(ctx.out(), "Destination Unreachable");
        default:
            throw std::runtime_error{std::format("Unexpected IP Protocol Type: {}", std::to_underlying(icmpType))};
        }
    }
};

template <> struct std::formatter<IcmpV4Header> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IcmpV4Header& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "ICMP Header of type {}, code {}, checksum 0x{:x}",
            header.mType, header.mCode, header.mCheckSum);
    }
};

template <> struct std::formatter<IcmpV4Echo> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IcmpV4Echo& echo, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "ICMP Echo, id {}, sequence number {}", 
            echo.mId, echo.mSeq);
    }
};
