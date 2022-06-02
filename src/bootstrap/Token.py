class Token:
    def __init__(self, typ, value, loc):
        self.typ = typ
        self.value = value
        self.loc = loc
        self.raw = str(self.value)

    def __repr__(self):
        return f"[{str(self.loc[0])}, {str(self.loc[1])}]\t {str(self.typ).ljust(10)}\t=> `{str(self.value)}`"
