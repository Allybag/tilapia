#include <tap.hpp>
#include <Arp.hpp>
#include <Ethernet.hpp>
#include <Icmp.hpp>
#include <Ip.hpp>
#include <Tcp.hpp>

#include <bit>
#include <iostream>
#include <iomanip>
#include <print>

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
        auto ethernetHeader = fromWire<EthernetHeader>(readBuffer);
        readOffset += sizeof(ethernetHeader);

        std::println("Received a message of size {}, Ethernet Header: {}", bytesRead, ethernetHeader);
        switch(ethernetHeader.mEthertype)
        {
            case EtherType::InternetProtocolVersion4:
            {
                auto ipHeader = fromWire<IpV4Header>(readBuffer + readOffset);
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

                        toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                        writeOffset += sizeof(ethernetResponseHeader);
                        toWire(ipResponseHeader, writeBuffer + writeOffset);
                        writeOffset += sizeof(ipResponseHeader);
                        toWire(response, writeBuffer + writeOffset);
                        writeOffset += sizeof(response);
                        break;
                    }
                    case IPProtocol::TCP:
                    {
                        auto tcpHeader = fromWire<TcpHeader>(readBuffer + readOffset);
                        readOffset += sizeof(tcpHeader);
                        std::println("{}", tcpHeader);
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

                            std::uint8_t zero{0};
                            TcpPseudoHeader pseudoHeader{ipResponseHeader.mSourceAddress, ipResponseHeader.mDestinationAddress, zero, IPProtocol::TCP, response->length()};
                            TcpPseudoPacket pseudoPacket{pseudoHeader, *response};
                            response->mCheckSum = checksum(pseudoPacket);

                            toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                            writeOffset += sizeof(ethernetResponseHeader);
                            toWire(ipResponseHeader, writeBuffer + writeOffset);
                            writeOffset += sizeof(ipResponseHeader);
                            toWire(*response, writeBuffer + writeOffset);
                            writeOffset += sizeof(*response);
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
                    auto ethernetResponseHeader{ethernetHeader};
                    std::swap(ethernetResponseHeader.mSourceMacAddress, ethernetResponseHeader.mDestinationMacAddress);
                    toWire(ethernetResponseHeader, writeBuffer + writeOffset);
                    writeOffset += sizeof(ethernetResponseHeader);

                    toWire(arpResponse->mHeader, writeBuffer + writeOffset);
                    writeOffset += sizeof(arpResponse->mHeader);

                    toWire(arpResponse->mBody, writeBuffer + writeOffset);
                    writeOffset += sizeof(arpResponse->mBody);
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
