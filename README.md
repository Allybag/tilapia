# Tilapia

A userspace TCP stack.

I will be mainly following along with
https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/

A tilapia is a kind of fish.

# Networking primer
There is an ISO standard called the OSI model, which describes
7 layers of abstraction for computers to communicate. These
layers are somewhat vague and theoretical, and actually mapping
specific protocols to layers can be a bit dubious.

## Layer 1
Layer 1 is the "Physical" layer, how bits actually move through
phsical space. This is completely outside our control.

## Layer 2
Layer 2 is the "Data Link" layer, where the unit of data is a frame.
We will only deal with Ethernet Frames. Ethernet and wi-fi
(or the IEEE 802.11 protocol) are actually pretty different
protocols, with a completely different frame format,
but you will pretty much never see a wi-fi frame on your computer.
This is basically because Ethernet came first, and wireless
network interfaces translate their frames into ethernet frames
before they are read by the operating system.
This works out pretty well for us.

Each Layer 2 device has a MAC (Media Access Control) address.
This is chosen when the network device is manufactured, never changes,
and should be globally unique.

We will be dealing with a TAP device, a simulated Layer 2 device.
When we create our device we are assigned a MAC address at random
by the operating system, but we can choose our own if we want to.

`ip link set address aa::bb::cc::dd::ee::ff Tilapia`

This means we will be sending and receiving Ethernet frames.

## Layer 2.5
We are also going to have to deal with a not very exciting protocol
called ARP, or Address Resolution Protocol.

This lets us map MAC Addresses, the only type of address which
exists at the Data Link Layer, to higher level addresses
such as IP Addresses.

As a translation layer, it doesn't fit that smoothly into the OSI Model.

## Layer 3
This is the network layer, where the unit of data is a packet.
This includes the IP, or Internet Protocol, of which we will only implement IPv4.
We will also have to implement ICMP, or the Intenet Control Message Protocol.

## Layer 4
This is the transport layer, where the unit of data is a segment
(or datagram, but not for us)
We'll be implementing TCP, or Transmission Control Protocol.
TCP is responsible for making sure our data arrives in a correct and consistent
fashion, for example by reordering out of order packets and rerequesting dropped packets.
This is all done invisibly to the layers above.

## Layers 5 - 7
These upper layers are also pretty vague, and we will also ignore them.


# Tilapia

The goal of this TCP stack is to show what is happening behind the scenes.
Tilapia will by default print a representation of the network protocols it receives.

We can toggle this behaviour on or off by sending a SIGUSR1 signal.
We can also toggle disabling all outbound writes with a SIGUSR2 signal.

To do this, just execute the following in a shell on the tilapia host:

kill -s SIGUSR1 $(pidof tilapia)
