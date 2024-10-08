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

    void zero_out_checksum()
    {
        mCheckSum = 0;
    }

    auto checksum() const
    {
        return mCheckSum;
    }
};
static_assert(sizeof(IcmpV4Header) == 4, "ICMP header must be 4 bytes long");

template <>
struct LayoutInfo<IcmpV4Header>
{
    static constexpr std::index_sequence<1, 1, 2> Sizes{};
};

struct IcmpV4Echo
{
    std::uint16_t mId;
    std::uint16_t mSeq;
    std::uint64_t mData;
    std::uint8_t mPayload[48];
} __attribute__((packed));
static_assert(sizeof(IcmpV4Echo) == 60, "ICMP Echo must be 60 bytes long");

template <>
struct LayoutInfo<IcmpV4Echo>
{
    static constexpr std::index_sequence<2, 2, 8, 48> Sizes{};
};

struct IcmpV4EchoResponse
{
    IcmpV4Header mHeader;
    IcmpV4Echo mBody;

    void zero_out_checksum()
    {
        mHeader.zero_out_checksum();
    }

    auto checksum() const
    {
        return mHeader.checksum();
    }
};

template <>
struct LayoutInfo<IcmpV4EchoResponse>
{
    static constexpr std::index_sequence<1, 1, 2, 2, 2, 8, 48> Sizes{};
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
