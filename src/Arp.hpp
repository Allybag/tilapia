#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstddef>
#include <cstdint>
#include <unordered_map>

using ArpProtoType = EtherType; // These are a subset apparently
static inline constexpr MacAddress ArpBroadcastAddress{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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

struct ArpMessage
{
    ArpHeader mHeader;
    ArpIpBody mBody;
};

using ArpKey = std::pair<ArpProtoType, IpAddress>;

namespace detail
{

inline void hash_combine(std::size_t&)
{
}

template <typename T, typename... Rest> inline void hash_combine(std::size_t& seed, const T& v, Rest... rest)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    hash_combine(seed, rest...);
}
} // namespace detail

template <typename... Rest> inline std::size_t hash_combine(Rest... rest)
{
    std::size_t hash{0};
    detail::hash_combine(hash, rest...);
    return hash;
}

namespace std
{
template <> struct hash<ArpProtoType>
{
    size_t operator()(const ArpProtoType& value) const
    {
        return std::hash<std::uint8_t>{}(std::to_underlying(value));
    }
};

template <> struct hash<IpAddress>
{
    size_t operator()(const IpAddress& value) const
    {
        return std::hash<std::uint32_t>{}(std::bit_cast<std::uint32_t>(value));
    }
};

template <> struct hash<ArpKey>
{
    size_t operator()(const ArpKey& arpKey) const
    {
        return hash_combine(arpKey.first, arpKey.second);
    }
};
}
// ARP allows us to translate from a protocol specific address like IP
// to an actual hardware MAC address
// We will only implement IP
class ArpNode
{
public:
    ArpNode(IpAddress ip, MacAddress mac) : mIp{ip}, mMac{mac} { }

    std::optional<ArpMessage> onMessage(const ArpMessage& message)
    {
        auto key = ArpKey{message.mHeader.mProtocolType, message.mBody.mSourceIp};
        mTranslationTable[key] = message.mBody.mSourceMacAddress;

        if (message.mBody.mDestinationIp != mIp || message.mHeader.mOpCode != ArpOpCode::Request)
        {
            return std::nullopt;
        }

        ArpMessage result{message};
        result.mHeader.mOpCode = ArpOpCode::Reply;
        result.mBody.mDestinationMacAddress = result.mBody.mSourceMacAddress;
        result.mBody.mSourceMacAddress = mMac;
        std::swap(result.mBody.mDestinationIp, result.mBody.mSourceIp);
        return result;
    }

    IpAddress address() const
    {
        return mIp;
    }

private:
    IpAddress mIp{};
    MacAddress mMac{};
    std::unordered_map<ArpKey, MacAddress> mTranslationTable{};
};


