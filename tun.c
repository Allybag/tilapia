#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#ifdef linux
#include <linux/if.h>
#include <linux/if_tun.h>
#else
struct ifreq
{
    int ifr_flags;
    char ifr_name[1];
};
#define IFF_TAP 0
#define IFF_NO_PI 0
#define IFNAMSIZ 1
#define TUNSETIFF 0
#endif


#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

#define TCP_FIN 1
#define TCP_SYN 2
#define TCP_RST 4
#define TCP_PSH 8
#define TCP_ACK 16
#define TCP_URG 32
#define TCP_ECE 64
#define TCP_CWR 128

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        printf("Cannot open TUN/TAP dev");
        exit(1);
    }

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if( *dev ) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        printf("ERR: Could not ioctl tun: %s\n", strerror(errno));
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main()
{
    char dev_name[100];
    tun_alloc(dev_name);
    printf("Created tunel device: %s", dev_name);
}
