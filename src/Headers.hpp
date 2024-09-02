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
    using HeaderLayout = LayoutInfo<HeaderT>;
    static_assert(totalSize(HeaderLayout::Sizes) == sizeof(HeaderT) || totalSize(HeaderLayout::Sizes) == 0);
    if constexpr (HeaderLayout::Sizes.size() == 0)
    {
        throw std::runtime_error{"No layout info for requested type"};
    }

    std::array<std::byte, sizeof(HeaderT)> bytes;
    std::memcpy(&bytes, buffer, sizeof(bytes));

    // We set the total size to 0 if we shouldn't byteswap the header
    if constexpr (totalSize(HeaderLayout::Sizes) != 0)
    {
        byteswapMembers(bytes, HeaderLayout::Sizes);
    }

    return std::bit_cast<HeaderT>(bytes);
}

template <typename HeaderT>
std::size_t toWire(const HeaderT& header, char* buffer)
{
    using HeaderLayout = LayoutInfo<HeaderT>;
    static_assert(totalSize(HeaderLayout::Sizes) == sizeof(HeaderT) || totalSize(HeaderLayout::Sizes) == 0);
    if constexpr (HeaderLayout::Sizes.size() == 0)
    {
        throw std::runtime_error{"No layout info for requested type"};
    }

    std::array<std::byte, sizeof(HeaderT)> bytes;
    std::memcpy(&bytes, &header, sizeof(bytes));

    if constexpr (totalSize(HeaderLayout::Sizes) != 0)
    {
        byteswapMembers(bytes, HeaderLayout::Sizes);
    }

    std::memcpy(buffer, &bytes, sizeof(bytes));
    return sizeof(HeaderT);
}
