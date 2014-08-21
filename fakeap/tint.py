import fcntl
import struct
import os
import threading
from scapy.layers.inet import Raw, IP

from constants import *


class TunInterface(threading.Thread):
    def __init__(self, ap, name="fakeap"):
        threading.Thread.__init__(self)

        if len(name) > IFNAMSIZ:
            raise Exception("Tun interface name cannot be larger than " + str(IFNAMSIZ))

        self.setDaemon(True)
        self.ap = ap
        self.fd = open('/dev/net/tun', 'r+b')

        ifr_flags = IFF_TUN | IFF_NO_PI  # Tun device without packet information
        ifreq = struct.pack('16sH', name, ifr_flags)
        fcntl.ioctl(self.fd, TUNSETIFF, ifreq)  # Syscall to create interface

        print("Created TUN interface %s" % name)

        # TODO set IP automatically...

    def write(self, pkt):
        os.write(self.fd.fileno(), str(pkt[IP]))  # Strip layer 2

    def read(self):
        raw_packet = os.read(self.fd.fileno(), DOT11_MTU)
        return raw_packet

    def close(self):
        os.close(self.fd.fileno())

    def run(self):
        while True:
            raw_packet = self.read()
            self.ap.callbacks.cb_tint_read(raw_packet)