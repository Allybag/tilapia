#pragma once

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <print>
#include <stdexcept>
#include <utility>

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

    if ((true))
    {
        std::println("Header: --------------------------------------------------");
        for(const auto byte: bytes)
        {
            std::println("{:x} ", static_cast<int>(byte));
        }
        std::println("");
    }

    byteswapMembers(bytes, LayoutInfo<HeaderT>::Sizes);

    if ((true))
    {
        std::println("Swapped: -------------------------------------------------");
        for (const auto byte: bytes)
        {
            std::println("{:x} ", static_cast<int>(byte));
        }
        std::println("");
        std::println("Header: --------------------------------------------------");
    }

    return std::bit_cast<HeaderT>(bytes);
}

