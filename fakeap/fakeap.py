
from scapy.all import *
from time import time, sleep
from .eap import *
from .utility import *
from .callbacks import Callbacks
from .constants import *


class FakeAccessPoint(object):
    class FakeBeaconTransmitter(threading.Thread):
        def __init__(self, ap):
            threading.Thread.__init__(self)
            self.ap = ap
            self.setDaemon(True)
            self.interval = 0.1

        def run(self):
            while True:
                for ssid in self.ap.ssids:
                    self.ap.callbacks.cb_dot11_beacon(ssid)

                # Sleep
                sleep(self.interval)

    def __init__(self, interface, channel, mac, wpa=False):
        self.ssids = []

        self.mac = mac
        self.ip = "192.168.3.1"
        self.channel = channel
        self.boottime = time()
        self.sc = 0
        self.aid = 0
        self.mutex = threading.Lock()
        self.wpa = wpa
        self.eap_manager = EAPManager()
        self.interface = interface

        self.beaconTransmitter = self.FakeBeaconTransmitter(self)
        self.beaconTransmitter.start()

        self.callbacks = Callbacks(self)

    def add_ssid(self, ssid):
        if not ssid in self.ssids and ssid != '':
            self.ssids.append(ssid)

    def remove_ssid(self, ssid):
        if ssid in self.ssids:
            self.ssids.remove(ssid)

    def current_timestamp(self):
        return (time() - self.boottime) * 1000000

    def next_sc(self):
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()

        return temp * 16  # Fragment number -> right 4 bits

    def next_aid(self):
        self.mutex.acquire()
        self.aid = (self.aid + 1) % 2008
        temp = self.aid
        self.mutex.release()

        return temp

    def get_radiotap_header(self):
        radiotap_packet = RadioTap(len = 18, present = 'Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded = '\x00\x6c' + get_frequency(self.channel) + '\xc0\x00\xc0\x01\x00\x00')
        return radiotap_packet

    def handle_dhcp(self, pkt):
        # TODO this DHCP handling is extremely basic. More features will be added later.
        serverIp = self.ip
        clientIp = "192.168.3.2" # For now just use only one client
        serverMac = self.mac
        clientMac = pkt.addr2
        subnetMask = "255.255.255.0"
        gateway = "0.0.0.0"

        #If DHCP Discover then DHCP Offer
        if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
            debug_print("DHCP Discover packet detected", 2)

            dhcpOfferPacket = self.get_radiotap_header() \
                            / Dot11(type = "Data", subtype = 0, addr1 = "ff:ff:ff:ff:ff:ff", addr2 = serverMac, SC = self.next_sc(), FCfield = 'from-DS') \
                            / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                            / SNAP(OUI = 0x000000, code = ETH_P_IP) \
                            / IP(src = serverIp, dst = clientIp) \
                            / UDP(sport=67, dport=68) \
                            / BOOTP(op = 2, yiaddr = clientIp, siaddr = serverIp, giaddr = gateway, chaddr = mac_to_bytes(clientMac), xid = pkt[BOOTP].xid) \
                            / DHCP(options = [('message-type', 'offer')]) \
                            / DHCP(options = [('subnet_mask', subnetMask)]) \
                            / DHCP(options = [('server_id', serverIp),('end')])

            sendp(dhcpOfferPacket, iface = self.interface, verbose = False)
            debug_print("DHCP Offer packet sent", 2)

        #If DHCP Request then DHCP Ack
        if DHCP in pkt and pkt[DHCP].options[0][1] == 3:
            debug_print("DHCP Request packet detected", 2)
            dhcpAckPacket = self.get_radiotap_header() \
                          / Dot11(type = "Data", subtype = 0, addr1 = "ff:ff:ff:ff:ff:ff", addr2 = serverMac, SC = self.next_sc(), FCfield = 'from-DS') \
                          / LLC(dsap = 0xaa, ssap = 0xaa, ctrl = 0x03) \
                          / SNAP(OUI = 0x000000, code = ETH_P_IP) \
                          / IP(src = serverIp, dst = clientIp) \
                          / UDP(sport = 67,dport = 68) \
                          / BOOTP(op = 2, yiaddr = clientIp, siaddr = serverIp, giaddr = gateway, chaddr = mac_to_bytes(clientMac), xid = pkt[BOOTP].xid) \
                          / DHCP(options = [('message-type','ack')]) \
                          / DHCP(options = [('server_id', serverIp)]) \
                          / DHCP(options = [('lease_time', 43200)]) \
                          / DHCP(options = [('subnet_mask', subnetMask)]) \
                          / DHCP(options = [('router', serverIp)]) \
                          / DHCP(options = [('name_server', DEFAULT_DNS_SERVER)]) \
                          / DHCP(options = [('domain', "localdomain")]) \
                          / DHCP(options = [('end')])
            sendp(dhcpAckPacket, iface = self.interface, verbose = False)
            debug_print("DHCP Ack packet sent", 2)

    def run(self):
        # TODO: Fix filter
        sniff(iface=self.interface, prn=self.callbacks.cb_recv_pkt, store=0, filter="")