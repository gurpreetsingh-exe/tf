
class Token:
    def __init__(self, type, value, loc, raw='', block=None):
        self.type = type
        self.value = value
        self.loc = loc
        self.raw = str(raw)
        self.block = block

    def __repr__(self):
        return f"{self.raw}, {self.type}, {self.value}"

class Block:
    def __init__(self, start, end):
        self.set(start, end)

    def set(self, start, end):
        self.start = start
        self.end = end
