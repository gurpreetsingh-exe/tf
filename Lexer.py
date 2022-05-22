import os
import sys
from typing import *
from token_types import *
from Token import Token
from token_types import Literal_

class Lexer:
    def __init__(self, program_file):
        self.program_file = program_file

        self.macros = {}
        self.include_files = []
        self.id = 0
        self.line = 0
        self.col = 0

        self.program = self.load_file()
        self.curr_char = self.program[self.id]

    def load_file(self):
        with open(self.program_file) as f:
            src = f.readlines()
            return self.pre_process(src)

    def advance(self):
        if self.curr_char == "\n":
            self.col = 0
            self.line += 1
        else:
            self.col += 1
        self.id += 1
        self.curr_char = self.program[self.id] if self.id < len(self.program) else None

    def eat(self, char):
        self.advance()
        if self.curr_char != char:
            sys.stdout.write(f"[{self.line}:{self.id % self.line}] ERROR: expected {char}")
            exit(1)

    def get_loc(self):
        if self.line < 0:
            return (0, 0,)
        else:
            return (self.line, self.col,)

    def lex_word(self, method):
        buffer = ''

        while self.curr_char != None and method(self) and (not self.curr_char.isspace()):
            buffer += self.curr_char
            self.advance()

        return buffer

    def lex(self):
        while self.curr_char != None:
            loc = self.get_loc()[:]
            if self.curr_char.isspace():
                self.advance()
                continue

            elif self.curr_char.isdigit():
                word = self.lex_word(lambda self: self.curr_char.isdigit())
                lit = Literal_(LiteralKind.INT, word)
                yield Token(TokenKind.LITERAL, lit, loc)

            elif self.curr_char.isalpha() or self.curr_char == "_":
                word = self.lex_word(lambda self: self.curr_char.isalnum() or self.curr_char == "_")

                if word in Keywords:
                    yield Token(Keywords[word], word, loc)
                elif word in Intrinsics:
                    intrinsic = Intrinsic(Intrinsics[word], word)
                    yield Token(TokenKind.INTRINSIC, intrinsic, loc)
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

    # TODO: This is sus, need a better system
    # Maybe after IR is implemented it would be
    # nice to refactor macros and includes as well
    def pre_process(self, src) -> str:
        for i in range(len(src)):
            line = src[i].split("//")[0]
            if "#include" in line:
                line = line.split("\n")[0].replace("#include ", "")
                inc_file_name = os.path.join("include", line.replace('"', ""))
                if inc_file_name in self.include_files:
                    src[i] = ""
                    continue
                self.include_files.append(inc_file_name)
                with open(inc_file_name, 'r') as inc:
                    src[i] = ""
                    contents = inc.readlines()
                    self.line -= len(contents) + 2
                    src = contents + src

        for i in range(len(src)):
            line = src[i].split("//")[0]
            if "#define" in line:
                line = line.replace("#define ", "")
                macro_name = line.split(" ")[0]
                if macro_name in self.macros:
                    sys.stdout.write(f"macro re-definition at line {i + 1}\n")
                    exit(1)
                self.macros[macro_name] = line.replace(macro_name, "").replace("\n", "").lstrip(" ")
                src[i] = src[i].replace(src[i], "\n")
                continue
            for macro_name, tokens in self.macros.items():
                ln = "".join(src[i].split("\n")).split(" ")
                if ln and macro_name in ln:
                    src[i] = src[i].replace(macro_name, tokens)

        return "".join(src)
