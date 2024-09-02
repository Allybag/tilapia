#include <tap.hpp>
#include <Arp.hpp>
#include <Ethernet.hpp>
#include <Icmp.hpp>
#include <Ip.hpp>
#include <Tcp.hpp>
#include <Vnet.hpp>

#include <bit>
#include <iostream>
#include <iomanip>
#include <print>
#include <vector>

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

    TapDevice tap{};
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
    VnetFlag mFlag;
    GenericSegmentOffloadType mGsoType;
    VnetHeader vnetWriteHeader{ VnetFlag::ChecksumValid, GenericSegmentOffloadType::None, 0, 0, 0, 0, 1};
    std::println("Will be writing virtual network header to all frames: {}", vnetWriteHeader);
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

        auto vnetHeader = fromWire<VnetHeader>(readBuffer);
        readOffset += sizeof(vnetHeader);
        std::println("Received a virtual network header, size {}, {}", bytesRead, vnetHeader);

        auto ethernetHeader = fromWire<EthernetHeader>(readBuffer + readOffset);
        readOffset += sizeof(ethernetHeader);

        std::println("Received a message of size {}, Ethernet Header: {}", bytesRead, ethernetHeader);
        switch(ethernetHeader.mEthertype)
        {
            case EtherType::InternetProtocolVersion4:
            {
                auto ipHeader = fromWire<IpV4Header>(readBuffer + readOffset);
                auto packetEndOffset = readOffset + ipHeader.mTotalLength;
                readOffset += sizeof(ipHeader);
                std::println("{}, checksum 0x{:x}", ipHeader, checksum(ipHeader));
                std::size_t myHeaderLen{ipHeader.mVersionLength.mLength};
                if (myHeaderLen != 5)
                {
                    std::println("Received an IP Header of length {}", myHeaderLen);
                    break;
                }
                switch(ipHeader.mProto)
                {
                    case IPProtocol::ICMP:
                    {
                        auto icmpHeader = fromWire<IcmpV4Header>(readBuffer + readOffset);
                        readOffset += sizeof(icmpHeader);
                        std::println("{}", icmpHeader);
                        if (icmpHeader.mType != IcmpType::EchoRequest)
                        {
                            break;
                        }

                        auto icmpEcho = fromWire<IcmpV4Echo>(readBuffer + readOffset);
                        readOffset += sizeof(icmpEcho);
                        std::println("{}", icmpEcho);

                        IcmpV4EchoResponse response{icmpHeader, icmpEcho};
                        response.mHeader.mType = IcmpType::EchoReply;
                        response.mHeader.mCheckSum = checksum(response);

                        auto ipResponseHeader{ipHeader};
                        std::swap(ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress);
                        ipResponseHeader.mCheckSum = checksum(ipResponseHeader);

                        auto ethernetResponseHeader{ethernetHeader};
                        std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);

                        writeOffset += toWire(vnetWriteHeader, writeBuffer + writeOffset);
                        writeOffset += toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                        writeOffset += toWire(ipResponseHeader, writeBuffer + writeOffset);
                        writeOffset += toWire(response, writeBuffer + writeOffset);
                        break;
                    }
                    case IPProtocol::TCP:
                    {
                        auto tcpHeader = fromWire<TcpHeader>(readBuffer + readOffset);
                        readOffset += sizeof(tcpHeader);
                        std::println("{}", tcpHeader);
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

                        for (const auto& option : options)
                        {
                            std::println("TcpOption: {}", option);
                        }

                        if (readOffset > packetEndOffset)
                        {
                            std::println("Read offset {} past packet end offset", readOffset, packetEndOffset);
                            std::cout << std::flush;
                            throw std::runtime_error{"Read past end of packet"};
                        }

                        auto payload = std::span<char>{readBuffer + readOffset, packetEndOffset - readOffset};
                        std::println("Received TCP Payload: {}", payload);


                        std::uint8_t zero{0};
                        TcpPseudoHeader pseudoReadHeader{ipHeader.mSourceAddress, ipHeader.mDestinationAddress, zero, IPProtocol::TCP, tcpHeader.length()};
                        TcpPseudoPacket pseudoReadPacket{pseudoReadHeader, tcpHeader};
                        auto read_checksum = tcp_checksum(pseudoReadPacket, options, payload);
                        std::println("TCP Receive checksum {} vs calculated {}", tcpHeader.checksum(), read_checksum);

                        auto [nodeIt, inserted] = tcpNodes.try_emplace(tcpHeader.mDestinationPort, tcpHeader.mDestinationPort, tcpHeader.mSourcePort);
                        auto response = nodeIt->second.onMessage(tcpHeader);
                        if (response.has_value())
                        {
                            std::println("{}", *response);

                            auto ethernetResponseHeader{ethernetHeader};
                            std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);

                            auto ipResponseHeader{ipHeader};
                            ipResponseHeader.mTotalLength = sizeof(ipResponseHeader) + sizeof(*response);
                            std::swap(ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress);
                            ipResponseHeader.mCheckSum = checksum(ipResponseHeader);

                            TcpPseudoHeader pseudoHeader{ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress, zero, IPProtocol::TCP, sizeof(TcpHeader)};
                            static constexpr auto cSoftwareTcpChecksums = true;
                            if constexpr (cSoftwareTcpChecksums)
                            {
                                TcpPseudoPacket pseudoPacket{pseudoHeader, *response};
                                response->mCheckSum = checksum(pseudoPacket);
                                writeOffset += toWire(vnetWriteHeader, writeBuffer + writeOffset);
                            }
                            else
                            {
                                constexpr auto cHeaderLength{sizeof(EthernetHeader) + sizeof(IpV4Header) + sizeof(TcpHeader)};
                                constexpr auto cGsoSize{1440};
                                constexpr auto cChecksumStart{sizeof(EthernetHeader) + sizeof(IpV4Header)};
                                constexpr auto cChecksumOffset{16};
                                constexpr auto cNumBuffers{1};
                                VnetHeader vnetTcpHeader{VnetFlag::NeedsChecksum, GenericSegmentOffloadType::TcpIp4, cHeaderLength, cGsoSize,
                                                         cChecksumStart, cChecksumOffset, cNumBuffers};
                                writeOffset += toWire(vnetTcpHeader, writeBuffer + writeOffset);
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
                std::println("{}", arpHeader);
                if (arpHeader.mProtocolType != ArpProtoType::InternetProtocolVersion4)
                {
                    continue;
                }

                auto arpIpBody = fromWire<ArpIpBody>(readBuffer + readOffset);
                readOffset += sizeof(arpIpBody);
                std::println("{}", arpIpBody);

                auto arpResponse = arpNode.onMessage({arpHeader, arpIpBody});
                if (arpResponse.has_value())
                {
                    std::println("Arp Response: Header {}, Body {}", arpResponse->mHeader, arpResponse->mBody);

                    writeOffset += toWire(vnetWriteHeader, writeBuffer + writeOffset);

                    auto ethernetResponseHeader{ethernetHeader};
                    std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);
                    writeOffset += toWire(ethernetResponseHeader, writeBuffer + writeOffset);

                    writeOffset += toWire(arpResponse->mHeader, writeBuffer + writeOffset);

                    writeOffset += toWire(arpResponse->mBody, writeBuffer + writeOffset);
                }
            }
            default:
                break;
        }

        if (writeOffset != 0)
        {
            int bytesWritten= write(tap.descriptor(), writeBuffer, writeOffset);
            if (bytesWritten != writeOffset)
            {
                std::println("Write failure! Only wrote {} out of {} bytes", bytesWritten, writeOffset);
            }
            std::println("Wrote a message of size {}", writeOffset);
        }

        std::cout << std::flush;
    }
}
