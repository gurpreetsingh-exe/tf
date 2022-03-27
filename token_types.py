from typing import Dict

__counter: int = 0
def __auto(reset: bool = False):
    global __counter
    if reset:
        __counter = 0
        return __counter
    __counter += 1
    return __counter

TOKEN_NUMBER: int = __auto(True)
TOKEN_OPEARTOR: int = __auto()
TOKEN_KEYWORD: int = __auto()
TOKEN_IDENTIFIER: int = __auto()
TOKEN_INTRINSIC: int = __auto()
TOKEN_SPECIAL_CHAR: int = __auto()
TOKEN_STRING_LITERAL: int = __auto()

# + =========== +
# |  Operators  |
# + =========== +

OP_PLUS: int = __auto()
OP_MINUS: int = __auto()
OP_EQ: int = __auto()
OP_LT: int = __auto()
OP_GT: int = __auto()
OP_DROP: int = __auto()
OP_SWAP: int = __auto()
OP_DUP: int = __auto()
OP_OVER: int = __auto()
OP_ROT: int = __auto()
OP_MEM: int = __auto()
OP_READ: int = __auto()
OP_WRITE: int = __auto()
OP_SHL: int = __auto()
OP_SHR: int = __auto()

OPS: Dict[str, int] = {
    '+': OP_PLUS,
    '-': OP_MINUS,
    '=': OP_EQ,
    '<': OP_LT,
    '>': OP_GT,
    'drop': OP_DROP,
    'swap': OP_SWAP,
    'dup': OP_DUP,
    'over': OP_OVER,
    'rot': OP_ROT,
    'mem': OP_MEM,
    '@': OP_READ,
    '&': OP_WRITE,
    'shl': OP_SHL,
    'shr': OP_SHR,
}

# + ========== +
# |  Keywords  |
# + ========== +

KEYWORD_IF: int = __auto()
KEYWORD_ELSE: int = __auto()
KEYWORD_DO: int = __auto()
KEYWORD_WHILE: int = __auto()
KEYWORD_FUNC: int = __auto()

KEYWORDS: Dict[str, int] = {
    "if": KEYWORD_IF,
    "else": KEYWORD_ELSE,
    "do": KEYWORD_DO,
    "while": KEYWORD_WHILE,
    "func": KEYWORD_FUNC,
}

# + ============ +
# |  Intrinsics  |
# + ============ +

INTRINSIC_PRINT: int = __auto()
INTRINSIC_SYSCALL1: int = __auto()
INTRINSIC_SYSCALL2: int = __auto()
INTRINSIC_SYSCALL3: int = __auto()
INTRINSIC_SYSCALL4: int = __auto()
INTRINSIC_SYSCALL5: int = __auto()
INTRINSIC_SYSCALL6: int = __auto()

INTRINSICS: Dict[str, int] = {
    'print': INTRINSIC_PRINT,
    'syscall1': INTRINSIC_SYSCALL1,
    'syscall2': INTRINSIC_SYSCALL2,
    'syscall3': INTRINSIC_SYSCALL3,
    'syscall4': INTRINSIC_SYSCALL4,
    'syscall5': INTRINSIC_SYSCALL5,
    'syscall6': INTRINSIC_SYSCALL6,
}

# + ==================== +
# |  Special Characters  |
# + ==================== +

LCURLY: int = __auto()
RCURLY: int = __auto()
LPAREN: int = __auto()
RPAREN: int = __auto()
DOUBLE_QUOTE: int = __auto()
COMMA: int = __auto()

SPECIAL_CHARS: Dict[str, int] = {
    '{': LCURLY,
    '}': RCURLY,
    '(': LPAREN,
    ')': RPAREN,
    '"': DOUBLE_QUOTE,
    ',': COMMA,
}
