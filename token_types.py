from typing import Dict
from enum import Enum, auto

class Repr:
    def __repr__(self):
        return f"{str(self.typ)}: {str(self.value)}"

class Literal_(Repr):
    def __init__(self, typ, value):
        self.typ = typ
        self.value = value

class LiteralKind(Enum):
    STR: int = auto()
    INT: int = auto()

class IntrinsicKind(Enum):
    DROP = auto()
    SWAP = auto()
    DUP = auto()
    OVER = auto()
    ROT = auto()
    MEM = auto()

    READ8 = auto()
    WRITE8 = auto()
    READ64 = auto()
    WRITE64 = auto()
    DIVMOD = auto()

    PRINT = auto()
    SYSCALL1 = auto()
    SYSCALL2 = auto()
    SYSCALL3 = auto()
    SYSCALL4 = auto()
    SYSCALL5 = auto()
    SYSCALL6 = auto()

Intrinsics: Dict[str, IntrinsicKind] = {
    "drop"    : IntrinsicKind.DROP,
    "swap"    : IntrinsicKind.SWAP,
    "dup"     : IntrinsicKind.DUP,
    "over"    : IntrinsicKind.OVER,
    "rot"     : IntrinsicKind.ROT,
    "mem"     : IntrinsicKind.MEM,
    "read8"    : IntrinsicKind.READ8,
    "write8"   : IntrinsicKind.WRITE8,
    "read64"  : IntrinsicKind.READ64,
    "write64" : IntrinsicKind.WRITE64,
    "divmod"  : IntrinsicKind.DIVMOD,
    "print"   : IntrinsicKind.PRINT,
    "syscall1": IntrinsicKind.SYSCALL1,
    "syscall2": IntrinsicKind.SYSCALL2,
    "syscall3": IntrinsicKind.SYSCALL3,
    "syscall4": IntrinsicKind.SYSCALL4,
    "syscall5": IntrinsicKind.SYSCALL5,
    "syscall6": IntrinsicKind.SYSCALL6,
}

class Intrinsic(Repr):
    def __init__(self, typ, value):
        self.typ = typ
        self.value = value

class TokenKind(Enum):
    LITERAL: int = auto()
    INTRINSIC: int = auto()
    IDENT: int = auto()

    FUNC: int = auto()
    IF: int = auto()
    ELSE: int = auto()
    DO: int = auto()
    WHILE: int = auto()

    PLUS        = auto()  # `+`
    MINUS       = auto()  # `-`
    STAR        = auto()  # `*`
    SLASH       = auto()  # `/`
    EQ          = auto()  # `=`
    SEMI        = auto()  # `;`
    LT          = auto()  # `<`
    GT          = auto()  # `>`
    COLON       = auto()  # `:`
    LPAREN      = auto()  # `(`
    RPAREN      = auto()  # `)`
    LCURLY      = auto()  # `{`
    RCURLY      = auto()  # `}`
    COMMA       = auto()  # `,`
    DOUBLEQUOTE = auto()  # `"`
    POUND       = auto()  # `#`
    AT          = auto()  # `@`
    AMPERSAND   = auto()  # `&`
    PIPE        = auto()  # `|`

    LT2        = auto()  # `<<`
    GT2        = auto()  # `>>`
    PIPE2      = auto()  # `||`
    AMPERSAND2 = auto()  # `&&`

    EOF         = auto()
    UNDEFINED   = auto()

Keywords: Dict[str, TokenKind] = {
    "if"   : TokenKind.IF,
    "else" : TokenKind.ELSE,
    "do"   : TokenKind.DO,
    "while": TokenKind.WHILE,
    "func" : TokenKind.FUNC,
}

Punctuators: Dict[str, TokenKind] = {
    '+': TokenKind.PLUS,
    '-': TokenKind.MINUS,
    '*': TokenKind.STAR,
    '/': TokenKind.SLASH,
    '=': TokenKind.EQ,
    ';': TokenKind.SEMI,
    '<': TokenKind.LT,
    '>': TokenKind.GT,
    ':': TokenKind.COLON,
    '(': TokenKind.LPAREN,
    ')': TokenKind.RPAREN,
    '{': TokenKind.LCURLY,
    '}': TokenKind.RCURLY,
    ',': TokenKind.COMMA,
    '"': TokenKind.DOUBLEQUOTE,
    '#': TokenKind.POUND,
    '@': TokenKind.AT,
    '&': TokenKind.AMPERSAND,
    '|': TokenKind.PIPE,
    '<<': TokenKind.LT2,
    '>>': TokenKind.GT2,
    '&&': TokenKind.AMPERSAND2,
    '||': TokenKind.PIPE2,
}
