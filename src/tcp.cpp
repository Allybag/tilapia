#include <tap.hpp>
#include <Ethernet.hpp>
#include <Ip.hpp>
#include <Arp.hpp>

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
                std::println("Checksum {}: {}", checksum(ipHeader), ipHeader);
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
