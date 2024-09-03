#pragma once

#include <constants.hpp>

#ifdef linux
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#include <dummy.hpp>
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include <print>

struct TapDevice
{
    explicit TapDevice(bool enableVnetHeader = false, std::string name = "Tilapia")
    {
        mFileDescriptor = open(cTunnelTapDevicePath, O_RDWR); 
        if (mFileDescriptor < 0)
        {
            std::println("Failed to open tap device");
            exit(1);
        }

        struct ifreq interfaceConfig{};
        strncpy(interfaceConfig.ifr_name, name.c_str(), IFNAMSIZ);
        // IFF_TUN      : TUN Device
        // IFF_TAP      : TAP Device
        // IFF_NO_PI    : No Packet Information
        // IFF_VNET_HDR : Prepend Ethernet frame with VNET Header
        interfaceConfig.ifr_flags = IFF_TAP | IFF_NO_PI;
        if (enableVnetHeader)
        {
            interfaceConfig.ifr_flags |=  IFF_VNET_HDR;
        }


        if (ioctl(mFileDescriptor, TUNSETIFF, static_cast<void*>(&interfaceConfig)) < 0)
        {
            std::println("Failed to configure tap device: {}", strerror(errno));
            close(mFileDescriptor);
            exit(1);
        }

        if (enableVnetHeader)
        {
            std::println("Will be reading and writing virtual network header on all frames");
            int vnetHeaderSize{12};
            if (ioctl(mFileDescriptor, TUNSETVNETHDRSZ, &vnetHeaderSize) < 0)
            {
                std::println("Failed to set VNET header size : {}", strerror(errno));
                close(mFileDescriptor);
                exit(1);
            }

            std::uint32_t offsetFlags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            if (ioctl(mFileDescriptor, TUNSETOFFLOAD, offsetFlags) < 0)
            {
                std::println("Failed to set tap device offset flags: {}", strerror(errno));
                close(mFileDescriptor);
                exit(1);
            }
        }

        mName = std::string{interfaceConfig.ifr_name};
    }

    int descriptor() const
    {
        return mFileDescriptor;
    }

    const std::string& name() const
    {
        return mName;
    }

private:
    static constexpr auto cTunnelTapDevicePath{"/dev/net/tun"};
    int mFileDescriptor{};
    std::string mName{};
};

