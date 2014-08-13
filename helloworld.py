# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.

from fakeap import FakeAccessPoint

ap = FakeAccessPoint('mon0', 1, '10:fe:ed:1d:ae:ca', False)
ap.add_ssid('Hello scapy-fakeap world!')
ap.run()