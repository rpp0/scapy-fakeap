

class Dot11SMState:
    SCANNING = 0
    UNAUTHENTICATED = 1
    UNASSOCIATED = 2
    ASSOCIATED = 3


class Dot11SM():
    def __init__(self):
        self.state = Dot11SMState.UNAUTHENTICATED

