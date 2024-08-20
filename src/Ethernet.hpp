#pragma once

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <format>
#include <print>
#include <utility>

enum class EtherType : std::uint16_t
{
    InternetProtocolVersion4 = 0x800,
    AddressResolutionProtocol = 0x806,
    ReverseAddressResolutionProtocol = 0x8035,
    InternetProtocolVersion6 = 0x86DD,
};

struct MacAddress
{
    char mValue[6];
};

struct EthernetHeader
{
    MacAddress mDestinationMacAddress;
    MacAddress mSourceMacAddress;
    EtherType  mEthertype;
};
static_assert(sizeof(EthernetHeader) == 14, "Ethernet header must be 14 bytes long");

template <std::size_t... Sizes>
constexpr std::size_t totalSize(std::index_sequence<Sizes...> sizes)
{
    if constexpr (sizes.size() == 0)
    {
        return 0;
    }
    else
    {
        return (Sizes + ...);
    }
}

template <typename HeaderT>
struct LayoutInfo
{
    static constexpr std::index_sequence<> Sizes{};

    static_assert(totalSize(Sizes) == sizeof(HeaderT));
};

template <>
struct LayoutInfo<EthernetHeader>
{
    static constexpr std::index_sequence<6, 6, 2> Sizes{};
};

template <std::size_t ArraySize, std::size_t MemberSize>
void byteswapMember(std::array<std::byte, ArraySize>& bytes, std::size_t& offset)
{
    std::ranges::reverse(bytes.begin() + offset, bytes.begin() + offset + MemberSize);
    offset += MemberSize;
}

template <std::size_t ArraySize, std::size_t... MemberSizes>
void byteswapMembers(std::array<std::byte, ArraySize>& bytes, std::index_sequence<MemberSizes...>)
{
    std::size_t offset{0};
    (byteswapMember<ArraySize, MemberSizes>(bytes, offset), ...);
}

template <typename HeaderT>
auto fromWire(const char* buffer) -> HeaderT
{
    if constexpr (LayoutInfo<HeaderT>::Sizes.size() == 0)
    {
        throw std::runtime_error{"No layout info for requested type"};
    }

    std::array<std::byte, sizeof(HeaderT)> bytes;
    std::memcpy(&bytes, buffer, sizeof(bytes));

    std::println("Header: --------------------------------------------------");
    for(const auto byte: bytes)
    {
        std::println("{:x} ", static_cast<int>(byte));
    }
    std::println("");

    byteswapMembers(bytes, LayoutInfo<HeaderT>::Sizes);


    for(const auto byte: bytes)
    {
        std::println("{:x} ", static_cast<int>(byte));
    }
    std::println("");

    auto header = std::bit_cast<HeaderT>(bytes);
    return header;
}

struct SimpleFormatter
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }
};

template <> struct std::formatter<EtherType> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const EtherType& etherType, FormatContext& ctx) const
    {
        using enum EtherType;
        switch (etherType)
        {
        case InternetProtocolVersion4:
            return std::format_to(ctx.out(), "IPv4");
        case AddressResolutionProtocol:
            return std::format_to(ctx.out(), "ARP");
        case ReverseAddressResolutionProtocol:
            return std::format_to(ctx.out(), "RARP");
        case InternetProtocolVersion6:
            return std::format_to(ctx.out(), "IPv6");
        default:
            throw std::runtime_error{std::format("Unexpected ethertype: {}", std::to_underlying(etherType))};
        }
    }
};

template <> struct std::formatter<MacAddress> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const MacAddress& address, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}", address.mValue[0], address.mValue[1],
        address.mValue[2], address.mValue[3], address.mValue[4], address.mValue[5]);
    }
};

template <> struct std::formatter<EthernetHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const EthernetHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{}: {} -> {}", header.mEthertype, header.mSourceMacAddress, header.mDestinationMacAddress);
    }
};
