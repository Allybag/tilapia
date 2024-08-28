#pragma once

#include <stddef.h>
#include <stdint.h>
#include <print>

uint32_t sum_every_16bits(void *addr, int count)
{
    uint32_t sum = 0;
    uint16_t * ptr = reinterpret_cast<uint16_t*>(addr);
    
    while( count > 1 )  {
        /*  This is the inner loop */
        std::println("Sami style: prior sum 0x{:x}, word 0x{:x}", sum, *ptr); 
        sum += * ptr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (uint8_t *) ptr;

    return sum;
}

uint16_t checksum(void *addr, int count, int start_sum)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     * Taken from https://tools.ietf.org/html/rfc1071
     */
    uint32_t sum = start_sum;

    std::println("Sami style: start sum 0x{:x}", sum);
    sum += sum_every_16bits(addr, count);
    std::println("Sami style: end sum 0x{:x}", sum);
    
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
    {
        std::println("Sami style: pre fold 0x{:x}", sum);
        sum = (sum & 0xffff) + (sum >> 16);
        std::println("Sami style: post fold 0x{:x}", sum);
    }

    std::println("Sami style: pre negate 0x{:x}", sum);
    return ~sum;
}

int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;


    std::println("Sami style: inital sum 0x{:x}", sum);
    sum += saddr;
    std::println("Sami style: post saddr 0x{:x}, 0x{:x}", sum, saddr);
    sum += daddr;
    std::println("Sami style: post daddr 0x{:x}, 0x{:x}", sum, daddr);
    sum += htons(proto);
    std::println("Sami style: post proto 0x{:x}, 0x{:x}", sum, htons(proto));
    sum += htons(len);
    std::println("Sami style: post len 0x{:x}, 0x{:x}", sum, htons(len));
    
    return checksum(data, len, sum);
}

#define SAMI_IP_TCP 6
int tcp_v4_checksum(uint8_t* data, uint32_t len, uint32_t saddr, uint32_t daddr)
{
    return tcp_udp_checksum(saddr, daddr, SAMI_IP_TCP, data, len);
}
#undef SAMI_IP_TCP

#if 0
    int tcp_v4_checksum(uint8_t* data, uint32_t len, uint32_t saddr, uint32_t daddr);
    auto saddr = std::byteswap(std::bit_cast<std::uint32_t>(pseudoHeader.mSourceIp));
    auto daddr = std::byteswap(std::bit_cast<std::uint32_t>(pseudoHeader.mDestinationAddress));
    char sami_buffer[100];
    toWire(*response, sami_buffer);
    auto sami_checksum = tcp_v4_checksum(reinterpret_cast<std::uint8_t*>(sami_buffer), sizeof(TcpHeader), saddr, daddr);
    std::println("Sami style checksum: 0x{:x}", std::byteswap(sami_checksum));
#endif
