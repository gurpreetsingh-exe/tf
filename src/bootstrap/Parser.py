from token_types import *
from Ast import *

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
    MOD = auto()

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
    TokenKind.PERCENT    : BinaryKind.MOD,
}

type_dict = {
    "i8"   : TypeKind.I8,
    "i16"  : TypeKind.I16,
    "i32"  : TypeKind.I32,
    "i64"  : TypeKind.I64,

    "f32"  : TypeKind.F32,
    "f64"  : TypeKind.F64,

    "str"  : TypeKind.STR,
    "bool" : TypeKind.BOOL,
}

expressions = [
    TokenKind.LITERAL,
    TokenKind.INTRINSIC,
    TokenKind.IDENT,
    TokenKind.TILDE,
    TokenKind.LET,
    TokenKind.AMPERSAND,
    TokenKind.AT,
] + list(BinaryOps.keys())

class Parser:
    def __init__(self, filepath, tokens):
        self.filepath = filepath
        self.tokens = tokens
        self.idx = 0
        self.curr_tok = self.tokens[self.idx]
        self.prev_tok = None
        self.has_return = False

        self.addr = 0

    def advance(self):
        self.prev_tok = self.curr_tok
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
            if typ not in type_dict:
                print(f"Unexpected type `{typ}`")
                exit(1)
            args.append(type_dict[typ])
            if self.curr_tok.typ == TokenKind.RPAREN:
                break
            else:
                self.expect(TokenKind.COMMA)
        self.expect(TokenKind.RPAREN)
        return FnSig(args, None)

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
            start_loc = self.curr_tok.loc
            if self.curr_tok.typ == TokenKind.LITERAL:
                lit = self.curr_tok.value
                if lit.typ == LiteralKind.INT:
                    ir = PushInt(lit.value)
                elif lit.typ == LiteralKind.FLOAT:
                    flt_addr = self.inc_addr_get()
                    ir = PushFloat(lit.value, flt_addr)
                elif lit.typ == LiteralKind.STR:
                    str_addr = self.inc_addr_get()
                    ir = PushStr(lit.value, str_addr)
                elif lit.typ == LiteralKind.BOOL:
                    ir = PushBool(lit.value)
                self.advance()
                ir.loc = start_loc
                yield ir
            elif self.curr_tok.typ in BinaryOps:
                op = self.curr_tok.typ
                self.advance()
                yield Binary(BinaryOps[op], None, start_loc)
            elif self.curr_tok.typ == TokenKind.INTRINSIC:
                intrinsic = self.curr_tok.value
                self.advance()
                yield Intrinsic(Intrinsics[intrinsic.value], start_loc)
            elif self.curr_tok.typ == TokenKind.IDENT:
                symbol = self.expect(TokenKind.IDENT).value
                if self.curr_tok.typ == TokenKind.LPAREN:
                    self.expect(TokenKind.LPAREN)
                    self.expect(TokenKind.RPAREN)
                    yield Call(symbol, start_loc)
                elif self.curr_tok.typ == TokenKind.BANG:
                    self.expect(TokenKind.BANG)
                    yield MacroCall(symbol, start_loc)
                else:
                    yield PushVar(symbol, start_loc)
            elif self.curr_tok.typ == TokenKind.TILDE:
                self.expect(TokenKind.TILDE)
                self.expect(TokenKind.LBRACKET)
                lit = self.expect(TokenKind.LITERAL).value
                if lit.typ != LiteralKind.INT:
                    print("Expected number in destruct operator")
                    exit(1)
                self.expect(TokenKind.RBRACKET)
                yield Destruct(lit.value, start_loc)
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
                yield Let(syms, start_loc)
            elif self.curr_tok.typ == TokenKind.AMPERSAND:
                self.advance()
                symbol = self.expect(TokenKind.IDENT).value
                yield PushAddr(symbol, start_loc)
            elif self.curr_tok.typ == TokenKind.AT:
                self.advance()
                symbol = self.expect(TokenKind.IDENT).value
                yield Deref(symbol, start_loc)
            else:
                return

    def stmt(self):
        while self.curr_tok != TokenKind.EOF:
            start_loc = self.curr_tok.loc
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
                yield If(body, if_addr, else_block, else_addr, start_loc)
            elif self.curr_tok.typ == TokenKind.DO:
                self.expect(TokenKind.DO)
                do_addr = self.addr
                end_addr = self.inc_addr_get()
                body = self.block()
                yield Do(body, do_addr, end_addr, start_loc)
            elif self.curr_tok.typ == TokenKind.WHILE:
                self.expect(TokenKind.WHILE)
                yield While(self.inc_addr_get(), start_loc)
            elif self.curr_tok.typ == TokenKind.CONST:
                self.expect(TokenKind.CONST)
                name = self.expect(TokenKind.IDENT).value
                lit = self.expect(TokenKind.LITERAL).value
                yield Const(name, lit.typ, lit.value, start_loc)
            elif self.curr_tok.typ == TokenKind.RETURN:
                self.expect(TokenKind.RETURN)
                yield Return(start_loc)
                self.has_return = True
            else:
                return

    def parse(self):
        while self.curr_tok != TokenKind.EOF:
            start_loc = self.curr_tok.loc
            if self.curr_tok.typ == TokenKind.EXTERN:
                self.advance()
            elif self.curr_tok.typ == TokenKind.FUNC:
                extern = self.prev_tok and self.prev_tok.typ == TokenKind.EXTERN
                self.expect(TokenKind.FUNC)
                symbol = self.expect(TokenKind.IDENT).value
                sign = self.func_sign()
                ret_type = None
                if self.curr_tok.typ == TokenKind.ARROW:
                    self.expect(TokenKind.ARROW)
                    ret_type = type_dict[self.expect(TokenKind.IDENT).value]
                body = None
                if self.curr_tok.typ == TokenKind.LCURLY:
                    body = self.block()
                sign.has_ret = self.has_return
                sign.ret_ty = ret_type
                yield Fn(symbol, sign, body, extern, start_loc)
                self.has_return = False
            elif self.curr_tok.typ == TokenKind.MACRO:
                self.expect(TokenKind.MACRO)
                macro_name = self.expect(TokenKind.IDENT).value
                self.expect(TokenKind.LCURLY)
                tokens = []
                while self.curr_tok.typ != TokenKind.RCURLY:
                    if self.curr_tok.typ == TokenKind.FUNC:
                        print("Cannot define function in a macro")
                        exit(1)
                    elif self.curr_tok.typ in [TokenKind.IF, TokenKind.ELSE, TokenKind.DO, TokenKind.WHILE]:
                        print("Cannot use if-else, do-while in a macro")
                        exit(1)
                    elif self.curr_tok.typ == TokenKind.MACRO:
                        print("Cannot define macro in a macro")
                        exit(1)
                    tokens += list(self.expr())
                self.expect(TokenKind.RCURLY)
                yield Macro(macro_name, tokens, start_loc)
            elif self.curr_tok.typ == TokenKind.IMPORT:
                self.expect(TokenKind.IMPORT)
                name = self.expect(TokenKind.IDENT).value
                yield Import(name, start_loc)
            else:
                yield from self.stmt()
