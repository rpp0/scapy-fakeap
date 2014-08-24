# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.

from fakeap import *

ap = FakeAccessPoint('mon0', 1, '10:fe:ed:1d:ae:ca', AP_WLAN_TYPE_OPEN)
ap.add_ssid('github.com/rpp0/scapy-fakeap')
ap.run()