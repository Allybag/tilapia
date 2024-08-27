#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>
#include <bit>

enum class TcpFlag : std::uint8_t
{
    // We define these backwards for byte order reasons
    CongestionWindowReduce = 1 << 7,
    ExplicitCongestion = 1 << 6,
    Urgent = 1 << 5,
    Ack = 1 << 4,
    Push = 1 << 3,
    Reset = 1 << 2,
    Syn = 1 << 1,
    Fin = 1 << 0,
};

struct TcpFlags
{
    std::uint8_t mValue;
};

struct TcpHeader
{
    std::uint16_t mSourcePort;
    std::uint16_t mDestinationPort;
    std::uint32_t mSequenceNumber;
    std::uint32_t mAcknowledgementNumber;
    std::uint8_t mReservedBits: 4; // These are swapped compared to spec
    std::uint8_t mHeaderLength: 4; // to deal with byte order
    TcpFlags mFlags;
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
    auto format(const TcpFlags& tcpFlags, FormatContext& ctx) const
    {
        const auto bits = std::bit_cast<std::uint8_t>(tcpFlags);
        std::format_to(ctx.out(), "Flags: ||");
        if(bits & std::to_underlying(TcpFlag::CongestionWindowReduce))
        {
            std::format_to(ctx.out(), "CongestionWindowReduce|");
        }
        else if(bits & std::to_underlying(TcpFlag::ExplicitCongestion))
        {
            std::format_to(ctx.out(), "ExplicitCongestion|");
        }
        else if(bits & std::to_underlying(TcpFlag::Urgent))
        {
            std::format_to(ctx.out(), "Urgent|");
        }
        else if(bits & std::to_underlying(TcpFlag::Ack))
        {
            std::format_to(ctx.out(), "Ack|");
        }
        else if(bits & std::to_underlying(TcpFlag::Push))
        {
            std::format_to(ctx.out(), "Push|");
        }
        else if(bits & std::to_underlying(TcpFlag::Reset))
        {
            std::format_to(ctx.out(), "Reset|");
        }
        else if(bits & std::to_underlying(TcpFlag::Syn))
        {
            std::format_to(ctx.out(), "Syn|");
        }
        else if(bits & std::to_underlying(TcpFlag::Fin))
        {
            std::format_to(ctx.out(), "Fin|");
        }

        std::format_to(ctx.out(), "|");
        return ctx.out();
    }
};


template <> struct std::formatter<TcpHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "TCP Header {}, size {}: {} -> {}",
            header.mFlags, header.mHeaderLength, header.mSourcePort, header.mDestinationPort);
    }
};

