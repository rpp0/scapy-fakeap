import platform

VERBOSITY = 1
RUNNING_ON_PI = platform.machine() == 'armv6l'
DEFAULT_DNS_SERVER = "8.8.8.8"
RSN = "\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00"
AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2