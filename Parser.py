from token_types import *

class IRKind(Enum):
    Func = auto()
    FuncSign = auto()
    Block = auto()
    PushInt = auto()
    PushStr = auto()
    PushVar = auto()
    Binary = auto()
    Intrinsic = auto()
    Call = auto()
    If = auto()
    Do = auto()
    While = auto()
    Destruct = auto()
    Let = auto()
    Const = auto()
    Return = auto()
    Import = auto()

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
    NOTEQ = auto()

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
    TokenKind.BANGEQ     : BinaryKind.NOTEQ,
}

expressions = [
    TokenKind.LITERAL,
    TokenKind.INTRINSIC,
    TokenKind.IDENT,
    TokenKind.TILDE,
    TokenKind.LET,
] + list(BinaryOps.keys())

class Parser:
    def __init__(self, filepath, tokens):
        self.filepath = filepath
        self.tokens = tokens
        self.idx = 0
        self.curr_tok = self.tokens[self.idx]
        self.has_return = False

        self.addr = 0

    def advance(self):
        if self.idx < len(self.tokens) - 1:
            self.idx += 1
            self.curr_tok = self.tokens[self.idx]
        else:
            self.curr_tok = TokenKind.EOF

    def expect(self, typ):
        tok = self.curr_tok
        if tok.typ != typ:
            print(f"{self.curr_tok.loc} Expected `{typ}` but got `{tok.typ}`")
            exit(1)
        self.advance()
        return tok

    def func_sign(self):
        args = []
        self.expect(TokenKind.LPAREN)
        while self.curr_tok.typ != TokenKind.RPAREN:
            typ = self.expect(TokenKind.IDENT).value
            if typ not in {'int', 'str', 'bool'}:
                print(f"Unexpected type `{typ}`")
            args.append(typ)
            if self.curr_tok.typ == TokenKind.RPAREN:
                break
            else:
                self.expect(TokenKind.COMMA)
        self.expect(TokenKind.RPAREN)
        return [IRKind.FuncSign, args]

    def block(self):
        self.expect(TokenKind.LCURLY)
        block = list(self.stmt())
        self.expect(TokenKind.RCURLY)
        return block

    def inc_addr_get(self):
        self.addr += 1
        return self.addr

    def expr(self):
        while self.curr_tok != TokenKind.EOF:
            if self.curr_tok.typ == TokenKind.LITERAL:
                lit = self.curr_tok.value
                if lit.typ == LiteralKind.INT:
                    ir = [IRKind.PushInt, lit.value]
                elif lit.typ == LiteralKind.STR:
                    str_addr = self.inc_addr_get()
                    ir = [IRKind.PushStr, lit.value, str_addr]
                self.advance()
                yield ir
            elif self.curr_tok.typ in BinaryOps:
                op = self.curr_tok.typ
                self.advance()
                yield [IRKind.Binary, BinaryOps[op]]
            elif self.curr_tok.typ == TokenKind.INTRINSIC:
                intrinsic = self.curr_tok.value
                self.advance()
                yield [IRKind.Intrinsic, intrinsic.value]
            elif self.curr_tok.typ == TokenKind.IDENT:
                symbol = self.expect(TokenKind.IDENT).value
                if self.curr_tok.typ == TokenKind.LPAREN:
                    self.expect(TokenKind.LPAREN)
                    self.expect(TokenKind.RPAREN)
                    yield [IRKind.Call, symbol]
                else:
                    yield [IRKind.PushVar, symbol]
            elif self.curr_tok.typ == TokenKind.TILDE:
                self.expect(TokenKind.TILDE)
                self.expect(TokenKind.LBRACKET)
                lit = self.expect(TokenKind.LITERAL).value
                if lit.typ != LiteralKind.INT:
                    print("Expected number in destruct operator")
                    exit(1)
                self.expect(TokenKind.RBRACKET)
                yield [IRKind.Destruct, lit.value]
            elif self.curr_tok.typ == TokenKind.LET:
                self.expect(TokenKind.LET)
                syms = []
                while self.curr_tok.typ != TokenKind.SEMI:
                    symbol = self.expect(TokenKind.IDENT).value
                    syms.append(symbol)
                    if self.curr_tok.typ == TokenKind.SEMI:
                        break
                    else:
                        self.expect(TokenKind.COMMA)
                self.expect(TokenKind.SEMI)
                yield [IRKind.Let, syms]
            else:
                return

    def stmt(self):
        while self.curr_tok != TokenKind.EOF:
            if self.curr_tok.typ in expressions:
                yield from self.expr()
            elif self.curr_tok.typ == TokenKind.IF:
                self.expect(TokenKind.IF)
                if_addr = self.inc_addr_get()
                body = self.block()
                else_block = None
                else_addr = None
                if self.curr_tok.typ == TokenKind.ELSE:
                    self.expect(TokenKind.ELSE)
                    else_addr = self.inc_addr_get()
                    else_block = self.block()
                yield [IRKind.If, body, if_addr, else_block, else_addr]
            elif self.curr_tok.typ == TokenKind.DO:
                self.expect(TokenKind.DO)
                do_addr = self.addr
                end_addr = self.inc_addr_get()
                body = self.block()
                yield [IRKind.Do, body, do_addr, end_addr]
            elif self.curr_tok.typ == TokenKind.WHILE:
                self.expect(TokenKind.WHILE)
                yield [IRKind.While, self.inc_addr_get()]
            elif self.curr_tok.typ == TokenKind.CONST:
                self.expect(TokenKind.CONST)
                name = self.expect(TokenKind.IDENT).value
                lit = self.expect(TokenKind.LITERAL).value
                yield [IRKind.Const, name, lit.typ, lit.value]
            elif self.curr_tok.typ == TokenKind.RETURN:
                self.expect(TokenKind.RETURN)
                yield [IRKind.Return]
                self.has_return = True
            else:
                return

    def parse(self):
        while self.curr_tok != TokenKind.EOF:
            if self.curr_tok.typ == TokenKind.FUNC:
                self.expect(TokenKind.FUNC)
                symbol = self.expect(TokenKind.IDENT).value
                sign = self.func_sign()
                body = self.block()
                sign.append(self.has_return)
                yield [IRKind.Func, symbol, sign, body]
                self.has_return = False
            elif self.curr_tok.typ == TokenKind.IMPORT:
                self.expect(TokenKind.IMPORT)
                name = self.expect(TokenKind.IDENT).value
                yield [IRKind.Import, name]
            else:
                yield from self.stmt()
