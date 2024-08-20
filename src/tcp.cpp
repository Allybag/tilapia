#include <tap.hpp>

#include <bit>
#include <iostream>
#include <iomanip>
#include <print>

int main()
{
    if constexpr (std::endian::native == std::endian::big)
    {
        std::println("Host is big endian");
    }
    else if constexpr (std::endian::native == std::endian::little)
    {
        std::println("Host is little endian");
    }
    else
    {
        std::println("Host is mixed endian");
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

        messagesRemaining -= 1;
        std::println("Received a message of size {}", bytesRead);
        std::cout << std::flush;
    }
}
