from typing import Tuple, Union, Optional

class Block:
    def __init__(self, start: Union[int, None] = None, end: Union[int, None] = None) -> None:
        self.set(start, end)

    def set(self, start: Union[int, None], end: Union[int, None]) -> None:
        self.start: Union[int, None] = start
        self.end: Union[int, None] = end

    def __repr__(self) -> str:
        return f"[s: {self.start}, e: {self.end}]"

class Token:
    def __init__(self, type: int, value: Union[str, bytes, int], loc: Tuple[int, int], raw: str = '', block: Block = Block()) -> None:
        self.type: int = type
        self.value: Union[str, bytes, int] = value
        self.loc: Tuple[int, int] = loc
        self.raw: str = str(raw)
        self.block: Block = block

    def __repr__(self) -> str:
        return f"r: {str(self.raw)}, t: {str(self.type)}, v: {str(self.value)}, b: {str(self.block)}, loc:({str(self.loc[0])}, {str(self.loc[1])})"
