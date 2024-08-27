#pragma once

#define IFF_TAP 0
#define IFF_NO_PI 0
#define IFNAMSIZ 16
#define TUNSETIFF 0
#define TUNSETOFFLOAD 0
#define TUN_F_CSUM 0
#define TUN_F_TSO4 0
#define TUN_F_TSO6 0

struct ifreq
{
    int ifr_flags;
    char ifr_name[IFNAMSIZ];
};
