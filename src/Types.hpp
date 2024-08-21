#pragma once

#include <format>

struct SimpleFormatter
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }
};

struct MacAddress
{
    char mValue[6];
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

struct IpAddress
{
    char mValue[4];
};

template <> struct std::formatter<IpAddress> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const IpAddress& address, FormatContext& ctx) const
    {
        return std::format_to(ctx.out(), "{}.{}.{}.{}", address.mValue[0], address.mValue[1],
        address.mValue[2], address.mValue[3]);
    }
};
