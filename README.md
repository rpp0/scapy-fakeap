scapy-fakeap
============

Fake wireless Access Point (AP) implementation using Python and Scapy, intended for convenient testing of 802.11 protocols and implementations. This library is a work in progress, and currently only supports open 802.11 networks.


Motivation
----------

Testing 802.11 protocols and implementations for bugs or security vulnerabilities requires a simple and flexible AP implementation. This library aims to provide these features by using the popular packet manipulation program 'Scapy' for data transmission and reception. 


Installation
------------

```python2 setup.py install```


Examples
--------

```python
# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.

from fakeap import FakeAccessPoint

ap = FakeAccessPoint('mon0', 1, '10:fe:ed:1d:ae:ca', False)
ap.add_ssid('Hello scapy-fakeap world!')
ap.run()
```

For more examples, please see the 'examples' folder.


Callbacks
---------

The behaviour of the AP can be completely customized by changing the callbacks associated with a certain event. To do this, pass a custom ```Callbacks()``` object to the ```FakeAccessPoint``` constructor or to an instance during runtime. Currently, the following callbacks are provided:

- ```cb_recv_pkt```: Triggered every time a packet is received. This callback defines when all other callbacks are triggered.
- ```cb_dot11_probe_req```: Triggered on reception of a Probe Request frame. The default behaviour is to reply with a Probe Response frame.
- ```cb_dot11_beacon```: Triggered every 0.1 seconds. The default behaviour is to send a Beacon frame.
- ```cb_dot11_auth```: Triggered on reception of an Authentication Request frame. The default behaviour is to reply with an Authentication Response frame.
- ```cb_dot11_assoc_req```: Triggered on reception of an Association Request frame. The default behaviour is to reply with an Association Response frame.
- ```cb_dot11_rts```: Triggered on reception of an RTS frame. The default behaviour is to reply with a CTS frame.
- ```cb_arp_req```: Triggered on reception of an ARP Request. The default behaviour is to reply with an ARP Response.
- ```cb_dot1X_eap_req```: Triggered on reception of an 802.1X EAP Request frame. The default behaviour is to reply with an 802.1X EAP Response frame.


### Writing your own callback:

The following example shows how a custom callback for a Callbacks() instance can be easily created:

```python
# This example demonstrates how to create a new callback for a specific Callbacks() instance.
# The callback will trigger each time an EAPOL packet is sniffed.

from types import MethodType
from fakeap import FakeAccessPoint, Callbacks
from scapy.layers.dot11 import EAPOL


def do_something(self):  # Our custom callback
    print("Got EAPOL packet!")


def my_recv_pkt(self, packet):  # We override recv_pkt to include a trigger for our callback
    if EAPOL in packet:
        self.cb_do_something()
    self.recv_pkt(packet)

ap = FakeAccessPoint('mon0', 1, '10:fe:ed:1d:ae:ca', True)
my_callbacks = Callbacks(ap)
my_callbacks.cb_recv_pkt = MethodType(my_recv_pkt, my_callbacks)
my_callbacks.cb_do_something = MethodType(do_something, my_callbacks)
ap.callbacks = my_callbacks

ap.add_ssid('My first callback!')
ap.run()
```