#pragma once

#include <Types.hpp>
#include <Ip.hpp>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <bit>

enum class TcpOptionType : std::uint8_t
{
    EndOfOptions = 0,
    NoOp = 1,
    MaximumSegmentSize = 2,
    WindowScale = 3,
    SelectiveAcknowledgementPermitted = 4,
    SelectiveAcknowledgemnt = 5, // Not yet implemented
    Timestamps = 8,
    UserTimeout = 28,
    Authentication = 29,
    Multipath = 30,
    FastOpen = 34,
};


template <> struct std::formatter<TcpOptionType> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpOptionType& optionType, FormatContext& ctx) const
    {
        using enum TcpOptionType;
        switch (optionType)
        {
        case TcpOptionType::EndOfOptions:
            return std::format_to(ctx.out(), "EndOfOptions");
        case TcpOptionType::NoOp:
            return std::format_to(ctx.out(), "NoOp");
        case TcpOptionType::MaximumSegmentSize:
            return std::format_to(ctx.out(), "MaximumSegmentSize");
        case TcpOptionType::WindowScale:
            return std::format_to(ctx.out(), "WindowScale");
        case TcpOptionType::SelectiveAcknowledgementPermitted:
            return std::format_to(ctx.out(), "SelectiveAcknowledgementPermitted");
        case TcpOptionType::SelectiveAcknowledgemnt:
            return std::format_to(ctx.out(), "SelectiveAcknowledgemnt");
        case TcpOptionType::Timestamps:
            return std::format_to(ctx.out(), "Timestamps");
        case TcpOptionType::UserTimeout:
            return std::format_to(ctx.out(), "UserTimeout");
        case TcpOptionType::Authentication:
            return std::format_to(ctx.out(), "Authentication");
        case TcpOptionType::Multipath:
            return std::format_to(ctx.out(), "Multipath");
        case TcpOptionType::FastOpen:
            return std::format_to(ctx.out(), "FastOpen");
        default:
            throw std::runtime_error{std::format("Unexpected TCP Option type: {}", std::to_underlying(optionType))};
        }
    }
};


struct TcpOption
{
    TcpOptionType mType;
    std::uint8_t mSize{1};
    std::uint32_t mData{};
    std::uint32_t mSecondData{};
};
static_assert(sizeof(TcpOption) == 12, "TCP Options must fit within 12 bytes");

template <>
auto fromWire<TcpOption>(const char* buffer) -> TcpOption
{
    TcpOption result{};

    result.mType = *reinterpret_cast<const TcpOptionType*>(buffer);
    switch (result.mType)
    {
        case TcpOptionType::EndOfOptions:
        case TcpOptionType::NoOp:
            return result;
    }

    auto asSizedInt = [buffer]<typename SizeT>(std::int64_t offset = 2) {
        SizeT myNetworkByteOrderNum = *reinterpret_cast<const SizeT*>(buffer + offset);
        return std::byteswap(myNetworkByteOrderNum);
    };

    result.mSize = asSizedInt.template operator()<std::uint8_t>(1);

    switch (result.mType)
    {
        case TcpOptionType::SelectiveAcknowledgementPermitted:
        case TcpOptionType::FastOpen:
            assert(result.mSize == 2);
            return result;
        case TcpOptionType::WindowScale:
            assert(result.mSize == 3);
            // Ridiculous syntax necessary to call a non deducible template lambda
            result.mData = asSizedInt.template operator()<std::uint8_t>();
            return result;
        case TcpOptionType::MaximumSegmentSize:
            assert(result.mSize == 4);
            result.mData = asSizedInt.template operator()<std::uint16_t>();
            return result;
        case TcpOptionType::Timestamps:
            assert(result.mSize == 10);
            result.mData = asSizedInt.template operator()<std::uint32_t>();
            result.mSecondData = asSizedInt.template operator()<std::uint32_t>(6);
            return result;
        case TcpOptionType::SelectiveAcknowledgemnt:
        case TcpOptionType::UserTimeout:
        case TcpOptionType::Authentication:
        case TcpOptionType::Multipath:
            std::println("Error: Received unsupported TCP Option: {}", std::to_underlying(result.mType));
    }

    return result;
}

template <>
std::size_t toWire(const TcpOption& option, char* buffer)
{
    char* writePointer{buffer};
    std::memcpy(writePointer, &option.mType, sizeof(option.mType));
    writePointer += sizeof(option.mType);
    switch (option.mType)
    {
        case TcpOptionType::EndOfOptions:
        case TcpOptionType::NoOp:
            return writePointer - buffer;
    }

    std::memcpy(writePointer, &option.mSize, sizeof(option.mSize));
    writePointer += sizeof(option.mSize);
    auto sizedIntoToWire = [&writePointer, &option]<typename SizeT>(bool secondary = false) {
        SizeT hostOrderVal = *reinterpret_cast<const SizeT*>(secondary ? &option.mSecondData : &option.mData);
        SizeT val{std::byteswap(hostOrderVal)}; 
        std::memcpy(writePointer, &val, sizeof(val));
        writePointer += sizeof(val);
    };

    switch (option.mType)
    {
        case TcpOptionType::SelectiveAcknowledgementPermitted:
        case TcpOptionType::FastOpen:
            assert(option.mSize == 2);
            std::println("Warning: Writing unsupported TCP Option: {}", std::to_underlying(option.mType));
            return writePointer - buffer;
        case TcpOptionType::WindowScale:
            assert(option.mSize == 3);
            sizedIntoToWire.template operator()<std::uint8_t>();
            return writePointer - buffer;
        case TcpOptionType::MaximumSegmentSize:
            assert(option.mSize == 4);
            sizedIntoToWire.template operator()<std::uint16_t>();
            return writePointer - buffer;
        case TcpOptionType::Timestamps:
            assert(option.mSize == 10);
            sizedIntoToWire.template operator()<std::uint32_t>();
            sizedIntoToWire.template operator()<std::uint32_t>(true);
            return writePointer - buffer;
        case TcpOptionType::SelectiveAcknowledgemnt:
        case TcpOptionType::UserTimeout:
        case TcpOptionType::Authentication:
        case TcpOptionType::Multipath:
            std::println("Error: Received unsupported TCP Option: {}", std::to_underlying(option.mType));
    }

    throw std::runtime_error{std::format("Could not write TCP Option {}", option.mType)};
}

template <> struct std::formatter<TcpOption> : SimpleFormatter
{
    template <typename FormatContext>
    auto format(const TcpOption& option, FormatContext& ctx) const
    {
        std::format_to(ctx.out(), "{}, size {}", option.mType, option.mSize);
        using enum TcpOptionType;
        switch (option.mType)
        {
        case TcpOptionType::EndOfOptions:
        case TcpOptionType::NoOp:
        case TcpOptionType::UserTimeout:
        case TcpOptionType::Authentication:
        case TcpOptionType::Multipath:
        case TcpOptionType::FastOpen:
            return ctx.out();
        case TcpOptionType::MaximumSegmentSize:
            return std::format_to(ctx.out(), ", data: {}", option.mData);
        case TcpOptionType::WindowScale:
            return std::format_to(ctx.out(), ", data: {}", option.mData);
        case TcpOptionType::SelectiveAcknowledgementPermitted:
            return std::format_to(ctx.out(), ", data: {}", option.mData);
        case TcpOptionType::SelectiveAcknowledgemnt:
            return std::format_to(ctx.out(), ", data: {}", option.mData);
        case TcpOptionType::Timestamps:
            return std::format_to(ctx.out(), ", data: {}, secondary data: {}", option.mData, option.mSecondData);
        default:
            throw std::runtime_error{std::format("Unexpected TCP Option type: {}", std::to_underlying(option.mType))};
        }
    }
};
