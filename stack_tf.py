#!/usr/bin/python

import sys
import subprocess

from token_types import *
from Token import *

def load_file(file_path):
    with open(file_path) as f:
        return f.readlines()

def parse_num(i, line):
    num = ''

    while i < len(line) and (not line[i].isspace()):
        num += line[i]
        i += 1

    return i, num

def parse_str(i, line):
    char_buf = ''

    while i < len(line) and line[i].isalnum() and (not line[i].isspace()):
        char_buf += line[i]
        i += 1

    return i, char_buf

def tokenize_program(lines):
    for row, line in enumerate(lines):
        i = 0
        line = ''.join(line.split("//")[0])
        while i < len(line):
            curr_char = line[i]
            if curr_char.isspace():
                i += 1
                continue
            elif curr_char.isdecimal():
                col = i
                i, num = parse_num(i, line)
                yield Token(TOKEN_NUMBER, num, (row + 1, col + 1), num)
            elif curr_char in OPS:
                yield Token(TOKEN_OPEARTOR, OPS[curr_char], (row + 1, i + 1), curr_char)
                i += 1
            elif curr_char.isalpha():
                col = i
                i, __str = parse_str(i, line)
                if __str in KEYWORDS:
                    yield Token(TOKEN_KEYWORD, KEYWORDS[__str], (row + 1, col + 1), __str)
                elif __str in INTRINSICS:
                    yield Token(TOKEN_INTRINSIC, INTRINSICS[__str], (row + 1, col + 1), __str)
                else:
                    sys.stdout.write(f"  [{row + 1}:{col + 1}] unexpected token {__str}\n")
                    exit(1)
            elif curr_char in SPECIAL_CHARS:
                yield Token(TOKEN_SPECIAL_CHAR, SPECIAL_CHARS[curr_char], (row + 1, i + 1), curr_char)
                i += 1
            else:
                assert False, "Unreachable"

def find_block_end(tokens):
    stack = []
    sep = []
    for i, tok in enumerate(tokens):
        if tokens[i].value == KEYWORD_IF:
            stack.append(tokens[i])
        elif tokens[i].value == KEYWORD_ELSE:
            if stack:
                if stack[-1].value != KEYWORD_IF:
                    sys.stdout.write(f"  [{tok.loc[0]}:{tok.loc[1]}] else without if\n")
                    exit(1)
                else:
                    stack.pop().block.end = i
                    stack.append(tokens[i])
        elif tokens[i].value == LCURLY:
            sep.append(tok)
            stack[-1].block = Block(i, None)
        elif tokens[i].value == RCURLY:
            stack[-1].block.end = i
            sep[-1].block = Block(None, i)
        else:
            continue
    return tokens

def run_program(tokens):
    stack = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.type == TOKEN_NUMBER:
            stack.append(int(tok.value))
            i += 1
        elif tok.type == TOKEN_OPEARTOR:
            a = stack.pop()
            b = stack.pop()
            if tok.value == OP_PLUS:
                stack.append(a + b)
            elif tok.value == OP_MINUS:
                stack.append(a - b)
            i += 1
        elif tok.type == TOKEN_KEYWORD:
            if tok.value == KEYWORD_IF:
                if stack.pop() == 0:
                    i = tok.block.end + 1
                else:
                    i += 1
            elif tok.value == KEYWORD_ELSE:
                i = tok.block.end
        elif tok.type == TOKEN_SPECIAL_CHAR:
            i += 1
        elif tok.type == TOKEN_INTRINSIC:
            if tok.value == INTRINSIC_PRINT:
                print(stack.pop())
            i += 1
        else:
            assert False, "unexpected token"

def compile_program(tokens):
    buffer = "section .text\n" + \
    "global _start\n" + \
    "print:\n" + \
    "    mov r8, -3689348814741910323\n" + \
    "    sub rsp, 40\n" + \
    "    mov BYTE [rsp+31], 10\n" + \
    "    lea r9, [rsp+30]\n" + \
    "    mov rcx, r9\n" + \
    ".L2:\n" + \
    "    mov rax, rdi\n" + \
    "    mul r8\n" + \
    "    mov rax, rdi\n" + \
    "    shr rdx, 3\n" + \
    "    lea rsi, [rdx+rdx*4]\n" + \
    "    add rsi, rsi\n" + \
    "    sub rax, rsi\n" + \
    "    mov rsi, rcx\n" + \
    "    sub rcx, 1\n" + \
    "    add eax, 48\n" + \
    "    mov BYTE [rcx+1], al\n" + \
    "    mov rax, rdi\n" + \
    "    mov rdi, rdx\n" + \
    "    cmp rax, 9\n" + \
    "    ja  .L2\n" + \
    "    lea edx, [r9+2]\n" + \
    "    mov eax, 32\n" + \
    "    mov edi, 1\n" + \
    "    sub edx, esi\n" + \
    "    movsx rdx, edx\n" + \
    "    sub rax, rdx\n" + \
    "    lea rsi, [rsp+rax]\n" + \
    "    mov rax, 1\n" + \
    "    syscall\n" + \
    "    add rsp, 40\n" + \
    "    ret\n" + \
    "_start:\n"

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.type == TOKEN_NUMBER:
            buffer += f"    ;; PUSH {tok.value}\n" + \
                      f"    push {tok.value}\n"
        elif tok.type == TOKEN_OPEARTOR:
            if tok.value == OP_PLUS:
                buffer += f"    ;; ADD\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    add rax, rbx\n" + \
                           "    push rax\n"
            elif tok.value == OP_MINUS:
                buffer += f"    ;; SUB\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    sub rax, rbx\n" + \
                           "    push rax\n"
        elif tok.type == TOKEN_KEYWORD:
            if tok.value == KEYWORD_IF:
                buffer += f"    pop rax\n" + \
                          f"    cmp rax, 0\n" + \
                          f"    je endif_{tok.block.end}\n" + \
                          f"if_{tok.block.start}:\n"
        elif tok.type == TOKEN_SPECIAL_CHAR:
            if tok.value == LCURLY:
                pass
            elif tok.value == RCURLY:
                buffer += f"endif_{i}:\n"
        elif tok.type == TOKEN_INTRINSIC:
            buffer += f"    pop rdi\n" + \
                       "    call print\n"
        i += 1
    buffer += "    ;; RET\n" + \
        "    mov rax, 60\n" + \
        "    mov rdi, 0\n" + \
        "    syscall\n"

    return buffer

def run_command(args):
    buf = '>>> '
    for arg in args:
        buf += arg + " "

    sys.stdout.write(buf + "\n")
    subprocess.call(args)

def execute(flag, program_file):
    program = load_file(program_file)
    tokens = list(tokenize_program(program))
    tokens = find_block_end(tokens)

    if flag == "-r":
        run_program(tokens)
    elif flag == "-c":
        buffer = compile_program(tokens)
        out_filename = program_file.split('.')[0]
        with open(out_filename + ".asm", "w") as out:
            out.write(buffer)

        run_command(["nasm", "-felf64", out_filename + ".asm"])
        run_command(["ld", "-o", out_filename, out_filename + ".o"])
        sys.stdout.write("\n")

def main(argv):
    exec_name = argv[0]
    argv = argv[1:]
    if len(argv) < 2:
        sys.stdout.write(f"{exec_name}: not enough arguments\n")
        exit(1)

    file_path, exec_flag = argv[1], argv[0]
    execute(exec_flag, file_path)

if __name__ == "__main__":
    main(sys.argv)
