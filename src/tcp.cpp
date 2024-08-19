#include <tun.hpp>

int main()
{
    char dev_name[IFNAMSIZ] = "Tilapia";
    tun_alloc(dev_name);
    printf("Created tunel device: %s", dev_name);
}
