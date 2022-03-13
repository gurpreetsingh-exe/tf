__counter = 0
def __auto(reset=False):
    global __counter
    if reset:
        __counter = 0
        return __counter
    __counter += 1
    return __counter

TOKEN_NUMBER = __auto(True)
TOKEN_OPEARTOR = __auto()
TOKEN_KEYWORD = __auto()
TOKEN_IDENTIFIER = __auto()
TOKEN_INTRINSIC = __auto()
TOKEN_SPECIAL_CHAR = __auto()
TOKEN_STRING_LITERAL = __auto()

# + =========== +
# |  Operators  |
# + =========== +

OP_PLUS = __auto()
OP_MINUS = __auto()
OP_EQ = __auto()
OP_LT = __auto()
OP_GT = __auto()
OP_DROP = __auto()
OP_SWAP = __auto()
OP_DUP = __auto()
OP_OVER = __auto()
OP_ROT = __auto()
OP_MEM = __auto()
OP_READ = __auto()
OP_WRITE = __auto()

OPS = {
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
}

# + ========== +
# |  Keywords  |
# + ========== +

KEYWORD_IF = __auto()
KEYWORD_ELSE = __auto()
KEYWORD_DO = __auto()
KEYWORD_WHILE = __auto()
KEYWORD_FUNC = __auto()

KEYWORDS = {
    "if": KEYWORD_IF,
    "else": KEYWORD_ELSE,
    "do": KEYWORD_DO,
    "while": KEYWORD_WHILE,
    "func": KEYWORD_FUNC,
}

# + ============ +
# |  Intrinsics  |
# + ============ +

INTRINSIC_PRINT = __auto()
INTRINSIC_SYSCALL3 = __auto()

INTRINSICS = {
    'print': INTRINSIC_PRINT,
    'syscall3': INTRINSIC_SYSCALL3,
}

# + ==================== +
# |  Special Characters  |
# + ==================== +

LCURLY = __auto()
RCURLY = __auto()
LPAREN = __auto()
RPAREN = __auto()
DOUBLE_QUOTE = __auto()
COMMA = __auto()

SPECIAL_CHARS = {
    '{': LCURLY,
    '}': RCURLY,
    '(': LPAREN,
    ')': RPAREN,
    '"': DOUBLE_QUOTE,
    ',': COMMA,
}
