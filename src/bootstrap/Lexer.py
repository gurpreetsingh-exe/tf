import sys
from typing import *
from .token_types import *
from .Token import Token
from .token_types import Literal_

class Lexer:
    def __init__(self, program_file):
        self.program_file = program_file

        self.macros = {}
        self.include_files = []
        self.id = 0
        self.loc = [0, 0]

        self.program = self.load_file()
        self.curr_char = self.program[self.id]

    def load_file(self):
        with open(self.program_file) as f:
            return "".join(f.readlines())

    def advance(self):
        if self.curr_char == "\n":
            self.loc[1] = 0
            self.loc[0] += 1
        else:
            self.loc[1] += 1
        self.id += 1
        self.curr_char = self.program[self.id] if self.id < len(self.program) else None

    def eat(self, char):
        self.advance()
        if self.curr_char != char:
            sys.stdout.write(f"[{self.loc[0]}:{self.id % self.loc[0]}] ERROR: expected {char}")
            exit(1)

    def lex_word(self, method):
        buffer = ''

        while self.curr_char != None and method(self) and (not self.curr_char.isspace()):
            buffer += self.curr_char
            self.advance()

        return buffer

    def lex(self):
        while self.curr_char != None:
            loc = self.loc[:]
            if self.curr_char.isspace():
                self.advance()
                continue

            elif self.curr_char.isdigit():
                word = self.lex_word(lambda self: self.curr_char.isdigit() or self.curr_char == ".")
                lit = Literal_(LiteralKind.INT if float(word).is_integer() else LiteralKind.FLOAT, str(word))
                yield Token(TokenKind.LITERAL, lit, loc)

            elif self.curr_char.isalpha() or self.curr_char == "_":
                word = self.lex_word(lambda self: self.curr_char.isalnum() or self.curr_char == "_")

                if word in Keywords:
                    yield Token(Keywords[word], word, loc)
                elif word in Intrinsics:
                    intrinsic = Intrinsic(Intrinsics[word], word)
                    yield Token(TokenKind.INTRINSIC, intrinsic, loc)
                elif word in {'true', 'false'}:
                    lit = Literal_(LiteralKind.BOOL, word)
                    yield Token(TokenKind.LITERAL, lit, loc)
                else:
                    yield Token(TokenKind.IDENT, word, loc)

            elif self.curr_char in Punctuators:
                if self.curr_char == '"':
                    buffer = ""
                    self.advance()
                    while self.curr_char != None and self.curr_char != '"':
                        buffer += self.curr_char
                        self.advance()
                    self.advance()
                    lit = Literal_(LiteralKind.STR, bytes(buffer, 'utf-8'))
                    yield Token(TokenKind.LITERAL, lit, loc)
                    continue

                prev = self.curr_char
                self.advance()
                compound = prev + self.curr_char
                if compound == "//":
                    while self.curr_char != "\n":
                        self.advance()
                    continue

                if compound in Punctuators:
                    yield Token(Punctuators[compound], compound, loc)
                    self.advance()
                else:
                    yield Token(Punctuators[prev], prev, loc)

            else:
                assert False, "unreachable"
