from token_types import *

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

    def parse(self):
        while self.curr_tok != TokenKind.EOF:
            print(self.curr_tok)
            self.advance()
