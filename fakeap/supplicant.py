
from scapy.all import sniff
from .callbacks import Callbacks
from rpyutils import check_root, get_frequency, if_hwaddr
from scapy.layers.dot11 import RadioTap, conf as scapyconf
from .dot11 import Dot11SM, Dot11SMState
from rpyutils import printd, Level
from time import sleep
import threading


class Supplicant(object):
    class Scanner(threading.Thread):
        def __init__(self, supplicant):
            threading.Thread.__init__(self)
            self.supplicant = supplicant
            self.setDaemon(True)
            self.interval = 1
            self.stop = False

        def run(self):
            # Give Scapy some time to boot
            sleep(1)
            while not self.stop:
                self.supplicant.associate_to_bssid()
                sleep(self.interval)

    def __init__(self, interface, bssid, bpffilter=""):
        self.callbacks = Callbacks(self)

        self.interface = interface
        self.channel = 1
        self.mac = if_hwaddr(interface)
        self.bssid = bssid
        self.sm = Dot11SM()
        self.scanner = self.Scanner(self)

        self.lfilter = None
        if bpffilter == "":
            self.bpffilter = "not ( wlan type mgt subtype beacon ) and ((ether dst host " + self.mac + ") or (ether dst host ff:ff:ff:ff:ff:ff))"
        else:
            self.bpffilter = bpffilter
        printd("BPF filter: " + self.bpffilter, Level.INFO)
        self.ip = '10.0.0.2/24'
        self.sc = 0

    def next_sc(self):
        self.sc = (self.sc + 1) % 4096
        temp = self.sc

        return temp * 16  # Fragment number -> right 4 bits

    def get_radiotap_header(self):
        radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(self.channel) + '\xc0\x00\xc0\x01\x00\x00')
        return radiotap_packet

    def associate_to_bssid(self):
        self.callbacks.cb_dot11_auth(self.bssid, 0x01)

    def run(self):
        check_root()
        self.scanner.start()

        scapyconf.iface = self.interface
        sniff(iface=self.interface, prn=self.callbacks.cb_recv_pkt_supp, store=0, filter=self.bpffilter)