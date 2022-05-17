from token_types import *

class IRKind(Enum):
    Func = auto()
    FuncSign = auto()
    Block = auto()
    PushInt = auto()
    PushStr = auto()
    Binary = auto()
    Intrinsic = auto()
    Call = auto()

class BinaryKind(Enum):
    ADD = auto()
    SUB = auto()
    MUL = auto()
    DIV = auto()
    LT = auto()
    GT = auto()
    SHL = auto()
    SHR = auto()
    AND = auto()
    OR = auto()
    EQ = auto()

BinaryOps = {
    TokenKind.PLUS       : BinaryKind.ADD,
    TokenKind.MINUS      : BinaryKind.SUB,
    TokenKind.STAR       : BinaryKind.MUL,
    TokenKind.SLASH      : BinaryKind.DIV,
    TokenKind.LT         : BinaryKind.LT,
    TokenKind.GT         : BinaryKind.GT,
    TokenKind.LT2        : BinaryKind.SHL,
    TokenKind.GT2        : BinaryKind.SHR,
    TokenKind.AMPERSAND2 : BinaryKind.AND,
    TokenKind.PIPE2      : BinaryKind.OR,
    TokenKind.EQ2        : BinaryKind.EQ,
}

class Parser:
    def __init__(self, filepath, tokens):
        self.filepath = filepath
        self.tokens = tokens
        self.idx = 0
        self.curr_tok = self.tokens[self.idx]

    def advance(self):
        if self.idx < len(self.tokens) - 1:
            self.idx += 1
            self.curr_tok = self.tokens[self.idx]
        else:
            self.curr_tok = TokenKind.EOF

    def expect(self, typ):
        tok = self.curr_tok
        if tok.typ != typ:
            print(f"Expected `{typ}` but got `{tok.typ}`")
            exit(1)
        self.advance()
        return tok

    def func_sign(self):
        sign = 0
        self.expect(TokenKind.LPAREN)
        while self.curr_tok.typ != TokenKind.RPAREN:
            self.advance()
        self.expect(TokenKind.RPAREN)
        return (IRKind.FuncSign, 0)

    def block(self):
        self.expect(TokenKind.LCURLY)
        block = list(self.stmt())
        self.expect(TokenKind.RCURLY)
        return block

    def stmt(self):
        while self.curr_tok != TokenKind.EOF:
            if self.curr_tok.typ == TokenKind.LITERAL:
                lit = self.curr_tok.value
                if lit.typ == LiteralKind.INT:
                    ir = (IRKind.PushInt, lit.value)
                elif lit.typ == LiteralKind.STR:
                    ir = (IRKind.PushStr, lit.value)
                yield ir
                self.advance()
            elif self.curr_tok.typ in BinaryOps:
                yield (IRKind.Binary, BinaryOps[self.curr_tok.typ])
                self.advance()
            elif self.curr_tok.typ == TokenKind.INTRINSIC:
                intrinsic = self.curr_tok.value
                yield (IRKind.Intrinsic, intrinsic.value)
                self.advance()
            elif self.curr_tok.typ == TokenKind.IDENT:
                # this must be a function call right?
                symbol = self.expect(TokenKind.IDENT).value
                yield (IRKind.Call, symbol)
            else:
                return

    def parse(self):
        while self.curr_tok != TokenKind.EOF:
            if self.curr_tok.typ == TokenKind.FUNC:
                self.expect(TokenKind.FUNC)
                symbol = self.expect(TokenKind.IDENT).value
                sign = self.func_sign()
                body = self.block()
                yield (IRKind.Func, symbol, sign, body)
            else:
                yield self.stmt()
