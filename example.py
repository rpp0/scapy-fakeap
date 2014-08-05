from fakeap.fakeap import FakeAccessPoint

test = FakeAccessPoint('mon0', 1, '10:fe:ed:1d:ae:ca', True)
test.add_ssid('testing')
test.run()