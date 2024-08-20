#include <tap.hpp>

#include <bit>
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

    int messagesRemaining{1};

    char buffer[2000];
    while (messagesRemaining)
    {
        if (read(tap.descriptor(), buffer, sizeof(buffer)) < 0)
        {
            std::print("Failed to read from Tap Device");
        }

        messagesRemaining -= 1;
        std::print("Received a message of size {}", strlen(buffer));
    }
}
