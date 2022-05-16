from typing import Tuple, Union

class Block:
    def __init__(self, start: Union[int, None] = None, end: Union[int, None] = None) -> None:
        self.set(start, end)

    def set(self, start: Union[int, None], end: Union[int, None]) -> None:
        self.start: Union[int, None] = start
        self.end: Union[int, None] = end

    def __repr__(self) -> str:
        return f"[s: {self.start}, e: {self.end}]"

class Literal_:
    def __init__(self, typ, value):
        self.typ = typ
        self.value = value

class Token:
    def __init__(self, type: int, value: Union[str, bytes, int], loc: Tuple[int, int]) -> None:
        self.type: int = type
        self.value: Union[str, bytes, int] = value
        self.loc: Tuple[int, int] = (loc[0], loc[1] + 1)
        self.raw: str = str(self.value)

    def __repr__(self) -> str:
        return f"t: {str(self.type)}, v: {str(self.value)}, loc:({str(self.loc[0])}, {str(self.loc[1])})"
