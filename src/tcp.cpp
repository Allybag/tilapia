#include <tap.hpp>

#include <print>

int main()
{
    TapDevice tap{};
    std::println("Created tap device {} : descriptor {}", tap.name(), tap.descriptor());
}
