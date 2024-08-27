#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>
#include <bit>

enum class TcpFlags : std::uint8_t
{
    CongestionWindowReduce = 1 << 0,
    ExplicitCongestion = 1 << 1,
    Urgent = 1 << 2,
    Ack = 1 << 3,
    Push = 1 << 4,
    Reset = 1 << 5,
    Syn = 1 << 6,
    Fin = 1 << 7,
};


struct TcpHeader
{
    std::uint16_t mSourcePort;
    std::uint16_t mDestinationPort;
    std::uint32_t mSequenceNumber;
    std::uint32_t mAcknowledgementNumber;
    std::uint8_t mReservedBits: 4; // These are swapped compared to spec
    std::uint8_t mHeaderLength: 4; // to deal with byte order
    std::uint8_t mFlags;
    std::uint16_t mWindowSize;
    std::uint16_t mCheckSum;
    std::uint16_t mUrgentPointer;

    void zero_out_checksum()
    {
        mCheckSum = 0;
    }

    auto checksum() const
    {
        return mCheckSum;
    }
};
static_assert(sizeof(TcpHeader) == 20, "TCP header must be 20 bytes long");

template <>
struct LayoutInfo<TcpHeader>
{
    static constexpr std::index_sequence<2, 2, 4, 4, 1, 1, 2, 2, 2> Sizes{};
};

template <> struct std::formatter<TcpFlags> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpFlags& tcpFlag, FormatContext& ctx) const
    {
        switch (tcpFlag)
        {
        case TcpFlags::CongestionWindowReduce:
            return std::format_to(ctx.out(), "CongestionWindowReduce");
        case TcpFlags::ExplicitCongestion:
            return std::format_to(ctx.out(), "ExplicitCongestion");
        case TcpFlags::Urgent:
            return std::format_to(ctx.out(), "Urgent");
        case TcpFlags::Ack:
            return std::format_to(ctx.out(), "Ack");
        case TcpFlags::Push:
            return std::format_to(ctx.out(), "Push");
        case TcpFlags::Reset:
            return std::format_to(ctx.out(), "Reset");
        case TcpFlags::Syn:
            return std::format_to(ctx.out(), "Syn");
        case TcpFlags::Fin:
            return std::format_to(ctx.out(), "Fin");
        default:
            throw std::runtime_error{std::format("Unexpected TCP Flag: {}", std::to_underlying(tcpFlag))};
        }
    }
};


template <> struct std::formatter<TcpHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "TCP Header num {}, size {}: {} -> {}",
            header.mSequenceNumber, header.mHeaderLength, header.mSourcePort, header.mDestinationPort);
    }
};

