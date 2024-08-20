#include <tap.hpp>
#include <Ethernet.hpp>

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

    int messagesRemaining{100};

    char buffer[2000];
    while (messagesRemaining)
    {
        int bytesRead = read(tap.descriptor(), buffer, sizeof(buffer));
        if (bytesRead < 0)
        {
            std::println("Failed to read from Tap Device");
        }

        if (bytesRead < sizeof(EthernetHeader))
        {
            std::println("Received dodgy message of size {}", bytesRead);
        }

        auto ethernetHeader = fromWire<EthernetHeader>(buffer);

        messagesRemaining -= 1;
        std::println("Received a message of size {}, type {:x}", bytesRead, ethernetHeader.mEthertype);
        std::cout << std::flush;
    }
}
