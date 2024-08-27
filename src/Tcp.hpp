#pragma once

#include <Headers.hpp>
#include <Types.hpp>
#include <Ip.hpp>

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

    bool set(TcpFlag flag) const
    {
        return mValue & std::to_underlying(flag);
    }

    TcpFlags operator|(TcpFlag flag) const
    {
        return TcpFlags(mValue | std::to_underlying(flag));
    }
};

using Port = std::uint16_t;
using SequenceNumber = std::uint32_t;

struct TcpHeader
{
    Port mSourcePort;
    Port mDestinationPort;
    SequenceNumber mSequenceNumber;
    SequenceNumber mAcknowledgementNumber;
    std::uint8_t mHeaderLength; // Actually 4 bits, followed by 4 bits of 0
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

    static constexpr auto cLengthOffsetBits{4};
    std::uint8_t length() const
    {
        return mHeaderLength >> cLengthOffsetBits;
    }

    void setLength(std::uint8_t length)
    {
        mHeaderLength = (length << cLengthOffsetBits);
    }
};
static_assert(sizeof(TcpHeader) == 20, "TCP header must be 20 bytes long");

template <>
struct LayoutInfo<TcpHeader>
{
    static constexpr std::index_sequence<2, 2, 4, 4, 1, 1, 2, 2, 2> Sizes{};
};

struct TcpPseudoHeader
{
    IpAddress mSourceIp;
    IpAddress mDestinationAddress;
    std::uint8_t mReservedZeros;
    IPProtocol mProtocol;
    std::uint16_t mTcpLength;
};
static_assert(sizeof(TcpPseudoHeader) == 12, "TCP psuedo header must be 12 bytes long");

template <>
struct LayoutInfo<TcpPseudoHeader>
{
    static constexpr std::index_sequence<4, 4, 1, 1, 2> Sizes{};
};

// Input to generate TCP Checksum
struct TcpPseudoPacket
{
    TcpPseudoHeader mPseudoHeader;
    TcpHeader mHeader;

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
struct LayoutInfo<TcpPseudoPacket>
{
    static constexpr std::index_sequence<4, 4, 1, 1, 2, 2, 2, 4, 4, 1, 1, 2, 2, 2> Sizes{};
};


template <> struct std::formatter<TcpFlags> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpFlags& tcpFlags, FormatContext& ctx) const
    {
        std::format_to(ctx.out(), "Flags: |");
        if (tcpFlags.set(TcpFlag::CongestionWindowReduce))
        {
            std::format_to(ctx.out(), "CongestionWindowReduce|");
        }
        else if (tcpFlags.set(TcpFlag::ExplicitCongestion))
        {
            std::format_to(ctx.out(), "ExplicitCongestion|");
        }
        else if (tcpFlags.set(TcpFlag::Urgent))
        {
            std::format_to(ctx.out(), "Urgent|");
        }
        else if (tcpFlags.set(TcpFlag::Ack))
        {
            std::format_to(ctx.out(), "Ack|");
        }
        else if (tcpFlags.set(TcpFlag::Push))
        {
            std::format_to(ctx.out(), "Push|");
        }
        else if (tcpFlags.set(TcpFlag::Reset))
        {
            std::format_to(ctx.out(), "Reset|");
        }
        else if (tcpFlags.set(TcpFlag::Syn))
        {
            std::format_to(ctx.out(), "Syn|");
        }
        else if (tcpFlags.set(TcpFlag::Fin))
        {
            std::format_to(ctx.out(), "Fin|");
        }
        else
        {
            std::format_to(ctx.out(), "|");
        }

        return ctx.out();
    }
};


template <> struct std::formatter<TcpHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "TCP Header {}, size {}: {} -> {}",
            header.mFlags, header.length(), header.mSourcePort, header.mDestinationPort);
    }
};

class TcpNode
{
public:
    TcpNode(Port port, Port remotePort) : mPort{port}, mRemotePort{remotePort} { }

    std::optional<TcpHeader> onMessage(const TcpHeader& header)
    {
        if (header.mFlags.set(TcpFlag::Syn))
        {
            TcpHeader result{header};
            std::swap(result.mSourcePort, result.mDestinationPort);
            result.mAcknowledgementNumber = header.mSequenceNumber + 1;
            result.mSequenceNumber = mSequenceNumber++;
            result.mFlags = (result.mFlags | TcpFlag::Ack);
            result.mCheckSum = 0;
            result.setLength(5);

            return result;
        }

        return std::nullopt;
    }

private:
    Port mPort;
    Port mRemotePort;
    SequenceNumber mSequenceNumber{8000};
};

