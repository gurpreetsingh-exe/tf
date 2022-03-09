
class Block:
    def __init__(self, start=None, end=None):
        self.set(start, end)

    def set(self, start, end):
        self.start = start
        self.end = end

    def __repr__(self):
        return f"[s: {self.start}, e: {self.end}]"

class Token:
    def __init__(self, type, value, loc, raw='', block=None):
        self.type = type
        self.value = value
        self.loc = loc
        self.raw = str(raw)
        self.block = block

    def __repr__(self):
        return f"r: {self.raw}, t: {self.type}, v: {self.value}, b: {self.block}, loc:({self.loc[0]}, {self.loc[1]})"
