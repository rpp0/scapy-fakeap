from fakeap.fakeap import FakeAccessPoint

test = FakeAccessPoint('mon0', 1, '00:c0:ca:33:44:55', '1', True)
test.addSSID('testing')
wait = raw_input('')