#pragma once

#include <Headers.hpp>
#include <Types.hpp>

#include <cstdint>
#include <cstring>
#include <format>
#include <print>
#include <utility>

struct EthernetHeader
{
    MacAddress mDestinationMacAddress;
    MacAddress mSourceMacAddress;
    EtherType  mEthertype;
};
static_assert(sizeof(EthernetHeader) == 14, "Ethernet header must be 14 bytes long");

template <>
struct LayoutInfo<EthernetHeader>
{
    static constexpr std::index_sequence<6, 6, 2> Sizes{};
};

template <> struct std::formatter<EthernetHeader> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const EthernetHeader& header, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{}: {} -> {}", header.mEthertype, header.mSourceMacAddress, header.mDestinationMacAddress);
    }
};
