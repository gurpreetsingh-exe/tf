from enum import Enum, auto

class Repr:
    def __repr__(self):
        return f"{str(self.typ)}: {str(self.value)}"

class Literal_(Repr):
    def __init__(self, typ, value):
        self.typ = typ
        self.value = value

class LiteralKind(Enum):
    STR = auto()
    INT = auto()

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
    SYSCALL = auto()

Intrinsics = {
    "drop"    : IntrinsicKind.DROP,
    "swap"    : IntrinsicKind.SWAP,
    "dup"     : IntrinsicKind.DUP,
    "over"    : IntrinsicKind.OVER,
    "rot"     : IntrinsicKind.ROT,
    "mem"     : IntrinsicKind.MEM,
    "read8"   : IntrinsicKind.READ8,
    "write8"  : IntrinsicKind.WRITE8,
    "read64"  : IntrinsicKind.READ64,
    "write64" : IntrinsicKind.WRITE64,
    "divmod"  : IntrinsicKind.DIVMOD,
    "print"   : IntrinsicKind.PRINT,
    "syscall": IntrinsicKind.SYSCALL,
}

class Intrinsic(Repr):
    def __init__(self, typ, value):
        self.typ = typ
        self.value = value

class TokenKind(Enum):
    LITERAL     = auto()
    INTRINSIC   = auto()
    IDENT       = auto()

    FUNC        = auto()
    IF          = auto()
    ELSE        = auto()
    DO          = auto()
    WHILE       = auto()

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
    LBRACKET    = auto()  # `[`
    RBRACKET    = auto()  # `]`
    COMMA       = auto()  # `,`
    DOUBLEQUOTE = auto()  # `"`
    POUND       = auto()  # `#`
    AT          = auto()  # `@`
    AMPERSAND   = auto()  # `&`
    PIPE        = auto()  # `|`
    TILDE       = auto()  # `~`

    LT2         = auto()  # `<<`
    GT2         = auto()  # `>>`
    PIPE2       = auto()  # `||`
    AMPERSAND2  = auto()  # `&&`
    EQ2         = auto()  # `==`

    EOF         = auto()
    UNDEFINED   = auto()

Keywords = {
    "if"   : TokenKind.IF,
    "else" : TokenKind.ELSE,
    "do"   : TokenKind.DO,
    "while": TokenKind.WHILE,
    "func" : TokenKind.FUNC,
}

Punctuators = {
    '+' : TokenKind.PLUS,
    '-' : TokenKind.MINUS,
    '*' : TokenKind.STAR,
    '/' : TokenKind.SLASH,
    '=' : TokenKind.EQ,
    ';' : TokenKind.SEMI,
    '<' : TokenKind.LT,
    '>' : TokenKind.GT,
    ':' : TokenKind.COLON,
    '(' : TokenKind.LPAREN,
    ')' : TokenKind.RPAREN,
    '{' : TokenKind.LCURLY,
    '}' : TokenKind.RCURLY,
    '[' : TokenKind.LBRACKET,
    ']' : TokenKind.RBRACKET,
    ',' : TokenKind.COMMA,
    '"' : TokenKind.DOUBLEQUOTE,
    '#' : TokenKind.POUND,
    '@' : TokenKind.AT,
    '&' : TokenKind.AMPERSAND,
    '|' : TokenKind.PIPE,
    '~' : TokenKind.TILDE,
    '<<': TokenKind.LT2,
    '>>': TokenKind.GT2,
    '&&': TokenKind.AMPERSAND2,
    '||': TokenKind.PIPE2,
    '==': TokenKind.EQ2,
}
