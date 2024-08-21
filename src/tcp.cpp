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

    ArpNode arpNode{IpAddress{10, 3, 3, 3}};
    std::println("Created Arp Node, IP: {}", arpNode.address());

    int messagesRemaining{100};

    char buffer[2000];
    while (messagesRemaining)
    {
        int bytesRead = read(tap.descriptor(), buffer, sizeof(buffer));
        messagesRemaining -= 1;
        if (bytesRead < 0)
        {
            std::println("Failed to read from Tap Device");
        }

        if (bytesRead < sizeof(EthernetHeader))
        {
            std::println("Received dodgy message of size {}", bytesRead);
        }

        std::size_t offset{0};
        auto ethernetHeader = fromWire<EthernetHeader>(buffer);
        offset += sizeof(ethernetHeader);

        std::println("Received a message of size {}, Ethernet Header: {}", bytesRead, ethernetHeader);
        switch(ethernetHeader.mEthertype)
        {
            case EtherType::InternetProtocolVersion4:
            {
                auto ipHeader = fromWire<IpV4Header>(buffer + offset);
                offset += sizeof(ipHeader);
                std::println("{}", ipHeader);
                break;
            }
            case EtherType::AddressResolutionProtocol:
            {
                auto arpHeader = fromWire<ArpHeader>(buffer + offset);
                offset += sizeof(arpHeader);
                std::println("{}", arpHeader);
                if (arpHeader.mProtocolType != ArpProtoType::InternetProtocolVersion4)
                {
                    continue;
                }

                auto arpIpBody = fromWire<ArpIpBody>(buffer + offset);
                offset += sizeof(arpIpBody);
                std::println("{}", arpIpBody);

                auto arpResponse = arpNode.onMessage({arpHeader, arpIpBody});
                if (arpResponse.has_value())
                {
                    std::println("Arp Response: Header {}, Body {}", arpResponse->mHeader, arpResponse->mBody);
                }
            }
            default:
                break;

        }

        std::cout << std::flush;
    }
}
