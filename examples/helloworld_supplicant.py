# Simple demonstration of the Supplicant from scapy-fakeap. Joins an open network.

from fakeap import *

supplicant = Supplicant('mon0', '00:00:00:00:00:00')
supplicant.run()