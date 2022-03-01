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
TOKEN_INTRINSIC = __auto()
TOKEN_SPECIAL_CHAR = __auto()

# + =========== +
# |  Operators  |
# + =========== +

OP_PLUS = __auto()
OP_MINUS = __auto()

OPS = {
    '+': OP_PLUS,
    '-': OP_MINUS,
}

# + ========== +
# |  Keywords  |
# + ========== +

KEYWORD_IF = __auto()
KEYWORD_ELSE = __auto()

KEYWORDS = {
    "if": KEYWORD_IF,
    "else": KEYWORD_ELSE,
}

# + ============ +
# |  Intrinsics  |
# + ============ +

INTRINSIC_PRINT = __auto()

INTRINSICS = {
    'print': INTRINSIC_PRINT,
}

# + ==================== +
# |  Special Characters  |
# + ==================== +

LCURLY = __auto()
RCURLY = __auto()

SPECIAL_CHARS = {
    "{": LCURLY,
    "}": RCURLY,
}
