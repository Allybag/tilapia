#include <tap.hpp>
#include <Arp.hpp>
#include <Ethernet.hpp>
#include <Icmp.hpp>
#include <Ip.hpp>
#include <Tcp.hpp>
#include <Vnet.hpp>

#include <atomic>
#include <bit>
#include <csignal>
#include <iostream>
#include <iomanip>
#include <numeric>
#include <print>
#include <string_view>
#include <vector>

struct FrameSection
{
    std::size_t size{};
    std::string name{};
    std::string payload{};

};

using FrameSections = std::vector<FrameSection>;

std::size_t totalSize(const FrameSections& sections)
{
    return std::accumulate(sections.begin(), sections.end(), 0, [](std::size_t sum, const FrameSection& it) { return sum + it.size; });
}

std::string print(const FrameSections& sections)
{
    auto size = totalSize(sections);
    std::string dashes(size + 1, '-');
    std::string line{};
    for (const auto& section : sections)
    {
        std::string segment{};
        segment.append("|");
        segment.append(section.name);

        if (section.payload.size())
        {
            segment.append(": ");
            segment.append(section.payload);
            // We don't want any newlines in our output
            segment.erase(std::remove(segment.begin(), segment.end(), '\n'), segment.cend());
        }

        int fill_count = section.size - segment.size();
        if (fill_count < 0)
        {
            std::println("Cannot print section {}, size {}", section.name, section.size);
            continue;
        }

        segment.append(std::string(fill_count, ' '));
        line.append(segment);
    }

    return std::format("{}\n{}|\n{}", dashes, line, dashes);
}

namespace sig
{
inline volatile std::sig_atomic_t gPrintPackets;
inline volatile std::sig_atomic_t gWritePackets;
}

inline void signal_handler(int signal)
{
    if (signal == SIGUSR1)
    {
        sig::gPrintPackets = !sig::gPrintPackets;
    }
    else if (signal == SIGUSR2)
    {
        sig::gWritePackets = !sig::gWritePackets;
    }
}


int main()
{
    if constexpr (std::endian::native == std::endian::little)
    {
        std::println("Host is little endian");
    }
    else
    {
        std::println("Host is not little endian, disaster!");
        return 1;
    }

    sig::gPrintPackets = true;
    sig::gWritePackets = true;
    std::signal(SIGUSR1, signal_handler);
    std::signal(SIGUSR2, signal_handler);

    static constexpr bool cEnableVnetHeader = false;
    TapDevice tap{cEnableVnetHeader};
    std::println("Created tap device {} : descriptor {}", tap.name(), tap.descriptor());

    // We do not set these yet, except for with ip command line tool
    // TODO: Bring interface up, set mac address
    IpAddress ip{fromQuartets({10, 3, 3, 3})};
    MacAddress mac{fromSextets({0xaa, 0xbb, 0xbb, 0x0, 0x0, 0xdd})};
    ArpNode arpNode{ip, mac};
    std::unordered_map<Port, TcpNode> tcpNodes{};
    std::println("Created Arp Node, IP: {}", arpNode.address());

    int messagesRemaining{100};

    char readBuffer[2000];
    char writeBuffer[2000];

    while (messagesRemaining)
    {
        int bytesRead = read(tap.descriptor(), readBuffer, sizeof(readBuffer));
        messagesRemaining -= 1;
        if (bytesRead < 0)
        {
            std::println("Failed to read from Tap Device");
        }

        if (bytesRead < sizeof(EthernetHeader))
        {
            std::println("Received dodgy message of size {}", bytesRead);
        }

        std::size_t readOffset{0};
        std::size_t writeOffset{0};

        auto writeVnetHeader = [&writeBuffer, &writeOffset]() -> std::size_t
        {
            if constexpr (!cEnableVnetHeader)
            {
                return 0;
            }

            VnetFlag mFlag;
            GenericSegmentOffloadType mGsoType;
            VnetHeader vnetWriteHeader{ VnetFlag::ChecksumValid, GenericSegmentOffloadType::None, 0, 0, 0, 0, 1};
            return toWire(vnetWriteHeader, writeBuffer + writeOffset);
        };

        if constexpr (cEnableVnetHeader)
        {
            auto vnetHeader = fromWire<VnetHeader>(readBuffer);
            readOffset += sizeof(vnetHeader);
            std::println("Received a virtual network header, size {}, {}", bytesRead, vnetHeader);
        }

        FrameSections sections{};
        auto ethernetHeader = fromWire<EthernetHeader>(readBuffer + readOffset);
        readOffset += sizeof(ethernetHeader);
        sections.emplace_back(FrameSection{sizeof(ethernetHeader), "Ethernet", {}});

        switch(ethernetHeader.mEthertype)
        {
            case EtherType::InternetProtocolVersion4:
            {
                auto ipHeader = fromWire<IpV4Header>(readBuffer + readOffset);
                auto packetEndOffset = readOffset + ipHeader.mTotalLength;
                readOffset += sizeof(ipHeader);
                sections.emplace_back(FrameSection{sizeof(ipHeader), "IPv4", {}});
                std::size_t myHeaderLen{ipHeader.mVersionLength.mLength};
                if (myHeaderLen != 5)
                {
                    break;
                }

                switch(ipHeader.mProto)
                {
                    case IPProtocol::ICMP:
                    {
                        auto icmpHeader = fromWire<IcmpV4Header>(readBuffer + readOffset);
                        readOffset += sizeof(icmpHeader);
                        sections.emplace_back(FrameSection{sizeof(icmpHeader), "ICMP", {}});
                        if (icmpHeader.mType != IcmpType::EchoRequest)
                        {
                            break;
                        }

                        auto icmpEcho = fromWire<IcmpV4Echo>(readBuffer + readOffset);
                        readOffset += sizeof(icmpEcho);
                        sections.emplace_back(FrameSection{sizeof(icmpEcho), "Echo", {}});

                        IcmpV4EchoResponse response{icmpHeader, icmpEcho};
                        response.mHeader.mType = IcmpType::EchoReply;
                        response.mHeader.mCheckSum = checksum(response);

                        auto ipResponseHeader{ipHeader};
                        std::swap(ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress);
                        ipResponseHeader.mCheckSum = checksum(ipResponseHeader);

                        auto ethernetResponseHeader{ethernetHeader};
                        std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);

                        writeOffset += writeVnetHeader();
                        writeOffset += toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                        writeOffset += toWire(ipResponseHeader, writeBuffer + writeOffset);
                        writeOffset += toWire(response, writeBuffer + writeOffset);
                        break;
                    }
                    case IPProtocol::TCP:
                    {
                        auto segmentStartOffset = readOffset;
                        auto tcpHeader = fromWire<TcpHeader>(readBuffer + readOffset);
                        readOffset += sizeof(tcpHeader);
                        std::vector<TcpOption> options{};
                        static constexpr auto cLengthUnits{4};
                        auto endOfOptions = readOffset + ((tcpHeader.length() * cLengthUnits) - sizeof(TcpHeader));
                        while (readOffset < endOfOptions)
                        {
                            auto tcpOption = fromWire<TcpOption>(readBuffer + readOffset);
                            options.push_back(tcpOption);
                            readOffset += tcpOption.mSize;
                        }

                        if (readOffset != endOfOptions)
                        {
                            std::println("Read to {}, past options end {}", readOffset, endOfOptions);
                            std::cout << std::flush;
                            throw std::runtime_error{"Read too many TCP options"};
                        }

                        if (readOffset > packetEndOffset)
                        {
                            std::println("Read offset {} past packet end offset", readOffset, packetEndOffset);
                            std::cout << std::flush;
                            throw std::runtime_error{"Read past end of packet"};
                        }

                        auto payload = std::string_view{readBuffer + readOffset, packetEndOffset - readOffset};
                        sections.emplace_back(FrameSection{packetEndOffset - segmentStartOffset, "TCP", std::string(payload)});

                        std::uint8_t zero{0};
                        TcpPseudoHeader pseudoReadHeader{ipHeader.mSourceAddress, ipHeader.mDestinationAddress, zero, IPProtocol::TCP, static_cast<std::uint16_t>(tcpHeader.length() * cLengthUnits + payload.size())};
                        TcpPseudoPacket pseudoReadPacket{pseudoReadHeader, tcpHeader};
                        auto read_checksum = tcp_checksum(pseudoReadPacket, options, payload);
                        if (read_checksum != tcpHeader.checksum())
                        {
                            std::println("TCP calculated checksum 0x{:x} does not match received 0x{:x}, will not Ack", tcpHeader.checksum(), read_checksum);
                            continue;
                        }

                        auto [nodeIt, inserted] = tcpNodes.try_emplace(tcpHeader.mDestinationPort, tcpHeader.mDestinationPort, tcpHeader.mSourcePort);
                        auto response = nodeIt->second.onMessage(tcpHeader, payload.size());
                        if (response.has_value())
                        {
                            if (payload.size())
                            {
                                std::print("{}", payload);
                            }

                            auto ethernetResponseHeader{ethernetHeader};
                            std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);

                            auto ipResponseHeader{ipHeader};
                            ipResponseHeader.mTotalLength = sizeof(ipResponseHeader) + sizeof(*response);
                            std::swap(ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress);
                            ipResponseHeader.mCheckSum = checksum(ipResponseHeader);

                            TcpPseudoHeader pseudoHeader{ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress, zero, IPProtocol::TCP, sizeof(TcpHeader)};
                            static constexpr auto cHardwareChecksums = false;
                            if constexpr (cHardwareChecksums)
                            {
                                static_assert(cHardwareChecksums == cEnableVnetHeader, "Cannot enable hardeware checksum without virtual network header");
                                constexpr auto cHeaderLength{sizeof(EthernetHeader) + sizeof(IpV4Header) + sizeof(TcpHeader)};
                                constexpr auto cGsoSize{1440};
                                constexpr auto cChecksumStart{sizeof(EthernetHeader) + sizeof(IpV4Header)};
                                constexpr auto cChecksumOffset{16};
                                constexpr auto cNumBuffers{1};
                                VnetHeader vnetTcpHeader{VnetFlag::NeedsChecksum, GenericSegmentOffloadType::TcpIp4, cHeaderLength, cGsoSize,
                                                         cChecksumStart, cChecksumOffset, cNumBuffers};
                                writeOffset += toWire(vnetTcpHeader, writeBuffer + writeOffset);
                            }
                            else
                            {
                                TcpPseudoPacket pseudoPacket{pseudoHeader, *response};
                                response->mCheckSum = checksum(pseudoPacket);
                                writeOffset += writeVnetHeader();
                            }

                            writeOffset += toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                            writeOffset += toWire(ipResponseHeader, writeBuffer + writeOffset);
                            writeOffset += toWire(*response, writeBuffer + writeOffset);
                        }
                    }
                    default:
                        break;
                }
                break;
            }
            case EtherType::AddressResolutionProtocol:
            {
                auto arpHeader = fromWire<ArpHeader>(readBuffer + readOffset);
                readOffset += sizeof(arpHeader);
                sections.emplace_back(FrameSection{sizeof(arpHeader), "ARP", {}});
                if (arpHeader.mProtocolType != ArpProtoType::InternetProtocolVersion4)
                {
                    continue;
                }

                auto arpIpBody = fromWire<ArpIpBody>(readBuffer + readOffset);
                readOffset += sizeof(arpIpBody);
                sections.emplace_back(FrameSection{sizeof(arpIpBody), "ARP IP", {}});

                auto arpResponse = arpNode.onMessage({arpHeader, arpIpBody});
                if (arpResponse.has_value())
                {
                    auto ethernetResponseHeader{ethernetHeader};
                    std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);

                    writeOffset += writeVnetHeader();
                    writeOffset += toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                    writeOffset += toWire(arpResponse->mHeader, writeBuffer + writeOffset);
                    writeOffset += toWire(arpResponse->mBody, writeBuffer + writeOffset);
                }
            }
            default:
                break;
        }

        if (sig::gPrintPackets)
        {
            auto sectionsSize = totalSize(sections);
            if (bytesRead > sectionsSize)
            {
                static constexpr auto cMaxUnknownSectionSize{80};
                auto size = std::min<std::size_t>(cMaxUnknownSectionSize, bytesRead - sectionsSize);
                sections.emplace_back(FrameSection{size, "Unknown", {}});
            }
            std::println("{}", print(sections));
        }

        if (sig::gWritePackets && writeOffset != 0)
        {
            int bytesWritten= write(tap.descriptor(), writeBuffer, writeOffset);
            if (bytesWritten != writeOffset)
            {
                std::println("Write failure! Only wrote {} out of {} bytes", bytesWritten, writeOffset);
            }
        }

        std::cout << std::flush;
    }
}
