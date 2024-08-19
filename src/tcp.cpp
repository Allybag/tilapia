#include <tap.hpp>

#include <print>

int main()
{
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
