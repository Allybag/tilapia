#pragma once

#include <Headers.hpp>
#include <Types.hpp>
#include <Ip.hpp>
#include <TcpOptions.hpp>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>

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

    void zero_out_checksum()
    {
    }

    auto checksum() const
    {
        return 0;
    }
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
static_assert(sizeof(TcpPseudoPacket) == sizeof(TcpPseudoHeader) + sizeof(TcpHeader));

template <>
struct LayoutInfo<TcpPseudoPacket>
{
    static constexpr std::index_sequence<4, 4, 1, 1, 2, 2, 2, 4, 4, 1, 1, 2, 2, 2> Sizes{};
};

inline std::uint16_t tcp_checksum(const TcpPseudoPacket& header, std::span<TcpOption> options, std::span<char> payload)
{
    std::uint16_t header_checksum_negated = checksum(header);
    std::uint16_t header_checksum = ~header_checksum_negated;
    std::uint16_t header_checksum_network_byte_order = std::byteswap(header_checksum);

    static constexpr auto cOptionBufferSize{60};
    char optionBuffer[cOptionBufferSize];
    auto optionWriteIndex = 0;
    for (const auto& option : options)
    {
        optionWriteIndex += toWire(option, optionBuffer + optionWriteIndex);
    }

    std::uint16_t options_checksum_negated_nbo = checksum(header_checksum_network_byte_order, optionBuffer, optionWriteIndex);
    std::uint16_t options_checksum_nbo = ~options_checksum_negated_nbo;

    std::uint16_t payload_checksum_nbo = checksum(options_checksum_nbo, payload.data(), payload.size());
    return std::byteswap(payload_checksum_nbo);
}

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
        if (tcpFlags.set(TcpFlag::ExplicitCongestion))
        {
            std::format_to(ctx.out(), "ExplicitCongestion|");
        }
        if (tcpFlags.set(TcpFlag::Urgent))
        {
            std::format_to(ctx.out(), "Urgent|");
        }
        if (tcpFlags.set(TcpFlag::Ack))
        {
            std::format_to(ctx.out(), "Ack|");
        }
        if (tcpFlags.set(TcpFlag::Push))
        {
            std::format_to(ctx.out(), "Push|");
        }
        if (tcpFlags.set(TcpFlag::Reset))
        {
            std::format_to(ctx.out(), "Reset|");
        }
        if (tcpFlags.set(TcpFlag::Syn))
        {
            std::format_to(ctx.out(), "Syn|");
        }
        if (tcpFlags.set(TcpFlag::Fin))
        {
            std::format_to(ctx.out(), "Fin|");
        }

        return ctx.out();
    }
};


template <> struct std::formatter<TcpHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "TCP Header {}, size {}, checksum 0x{:x}: {} -> {}",
            header.mFlags, header.length(), header.mCheckSum, header.mSourcePort, header.mDestinationPort);
    }
};

class TcpNode
{
public:
    TcpNode(Port port, Port remotePort) : mPort{port}, mRemotePort{remotePort} { }

    std::optional<TcpHeader> onMessage(const TcpHeader& header, std::size_t payload_size)
    {
        TcpHeader result{header};
        std::swap(result.mSourcePort, result.mDestinationPort);
        result.mSequenceNumber = mSequenceNumber;
        result.mCheckSum = 0;
        result.setLength(5);
        result.mFlags.mValue = std::to_underlying(TcpFlag::Ack);
        result.mAcknowledgementNumber = header.mSequenceNumber + payload_size;

        if (header.mFlags.set(TcpFlag::Syn))
        {
            assert(payload_size == 0);
            result.mFlags = result.mFlags | TcpFlag::Syn;
            result.mSequenceNumber = mSequenceNumber++;
            result.mAcknowledgementNumber = header.mSequenceNumber + 1;
        }

        if (mLastAcked == result.mAcknowledgementNumber)
        {
            // Already acknowledged all received data
            return std::nullopt;
        }

        mLastAcked = result.mAcknowledgementNumber;
        return result;
    }

private:
    Port mPort;
    Port mRemotePort;
    SequenceNumber mSequenceNumber{8000};
    SequenceNumber mLastAcked{0};
};

