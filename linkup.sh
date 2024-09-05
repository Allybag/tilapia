ip link set dev Tilapia up  # Bring the interface up
ip link set address aa:bb:bb:00:00:dd Tilapia # Set our custom MAC address
ip addr add 10.3.3.0/24 dev Tilapia  # Give our interface an address
ip route get 10.3.3.3  # Check that packets to 10.3.3.x are going through our interface
