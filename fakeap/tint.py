from constants import *
import fcntl
import struct
import os
from scapy.layers.inet import IP


class TunInterface():
    def __init__(self, name):
        if len(name) > IFNAMSIZ:
            raise Exception("Tun interface name cannot be larger than " + str(IFNAMSIZ))

        self.fd = open('/dev/net/tun', 'r+b')
        ifr_flags = IFF_TUN | IFF_NO_PI  # Tun device without packet information
        ifreq = struct.pack('16sH', name, ifr_flags)
        fcntl.ioctl(self.fd, TUNSETIFF, ifreq)  # Syscall to create interface
        print("Created interface %s" % name)

        # TODO set IP automatically...

    def write(self, pkt):
        os.write(self.fd.fileno(), str(pkt[IP]))  # Strip layer 2

    def read(self):
        raw_packet = os.read(self.fd.fileno(), MAX_PKT_SIZE)
        return raw_packet

    def close(self):
        os.close(self.fd.fileno())