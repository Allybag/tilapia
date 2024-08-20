#pragma once

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <print>
#include <ranges>
#include <span>

struct EthernetHeader
{
    char mDestinationMacAddress[6];
    char mSourceMacAddress[6];
    std::uint16_t mEthertype{};
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


