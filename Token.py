from typing import Tuple, Union

class Block:
    def __init__(self, start: Union[int, None] = None, end: Union[int, None] = None) -> None:
        self.set(start, end)

    def set(self, start: Union[int, None], end: Union[int, None]) -> None:
        self.start: Union[int, None] = start
        self.end: Union[int, None] = end

    def __repr__(self) -> str:
        return f"[s: {self.start}, e: {self.end}]"

class Token:
    def __init__(self, type: int, value: Union[str, bytes, int], loc: Tuple[int, int], block: Block = Block(), args: int = 0) -> None:
        self.type: int = type
        self.value: Union[str, bytes, int] = value
        self.loc: Tuple[int, int] = (loc[0], loc[1] + 1)
        self.raw: str = str(self.value)
        self.block: Block = block
        self.args: int = args

    def __repr__(self) -> str:
        return f"t: {str(self.type)}, v: {str(self.value)}, b: {str(self.block)}, loc:({str(self.loc[0])}, {str(self.loc[1])})"
