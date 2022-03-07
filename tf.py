#!/usr/bin/python

import sys
import subprocess

from token_types import *
from Token import *

def load_file(file_path):
    with open(file_path) as f:
        src = f.readlines()
        return pre_process(src)

macros = {}

def pre_process(src):
    for i in range(len(src)):
        line = src[i]
        if "#define" in line:
            line = line.replace("#define ", "")
            macro_name = line.split(" ")[0]
            if macro_name in macros:
                sys.stdout.write(f"macro re-definition at line {i + 1}\n")
                exit(1)
            macros[macro_name] = line.replace(macro_name, "").lstrip(" ")
            src[i] = src[i].replace(src[i], "\n")
            continue
        for macro_name, tokens in macros.items():
            if macro_name in line:
                src[i] = src[i].replace(macro_name, tokens)

    return src

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
                elif __str in OPS:
                    yield Token(TOKEN_OPEARTOR, OPS[__str], (row + 1, col + 1), __str)
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
    for i, tok in enumerate(tokens):
        if tok.value == KEYWORD_IF:
            stack.append(tok)
        elif tok.value == KEYWORD_ELSE:
            stack.pop().block.end = i
            stack.append(tok)
        elif tok.value == KEYWORD_DO:
            tok.block = Block(i, None)
            stack.append(tok)
        elif tok.value == KEYWORD_WHILE:
            tok.block = stack.pop().block
        elif tok.value == RCURLY:
            if stack[-1].value == KEYWORD_DO:
                continue
            stack[-1].block = Block(None, i)
            if i + 1 < len(tokens) and tokens[i + 1].value != KEYWORD_ELSE:
                stack.pop()
        else:
            continue
    return tokens

def lslice(lst, i):
    return lst[i:], lst[:i]

MEM_CAPACITY = 1024

def run_program(tokens):
    stack = []
    i = 0
    mem = bytearray(MEM_CAPACITY)

    while i < len(tokens):
        tok = tokens[i]
        if tok.type == TOKEN_NUMBER:
            stack.append(int(tok.value))
            i += 1
        elif tok.type == TOKEN_OPEARTOR:
            if tok.value == OP_PLUS:
                [b, a], stack = lslice(stack, -2)
                stack.append(a + b)
            elif tok.value == OP_MINUS:
                [b, a], stack = lslice(stack, -2)
                stack.append(b - a)
            elif tok.value == OP_EQ:
                [b, a], stack = lslice(stack, -2)
                stack.append(int(a == b))
            elif tok.value == OP_LT:
                [b, a], stack = lslice(stack, -2)
                stack.append(int(b < a))
            elif tok.value == OP_GT:
                [b, a], stack = lslice(stack, -2)
                stack.append(int(b > a))
            elif tok.value == OP_DROP:
                stack.pop()
            elif tok.value == OP_SWAP:
                [b, a], stack = lslice(stack, -2)
                stack.append(a)
                stack.append(b)
            elif tok.value == OP_DUP:
                stack.append(stack[-1])
            elif tok.value == OP_OVER:
                stack.append(stack[-2])
            elif tok.value == OP_ROT:
                last3, stack = lslice(stack, -3)
                last2, [last] = lslice(last3, -2)
                last2.append(last)
                stack.extend(last2)
            elif tok.value == OP_MEM:
                stack.append(0)
            elif tok.value == OP_READ:
                a = stack.pop()
                stack.append(mem[a])
            elif tok.value == OP_WRITE:
                [b, a], stack = lslice(stack, -2)
                mem[b] = a & 0xff
            i += 1
        elif tok.type == TOKEN_KEYWORD:
            if tok.value == KEYWORD_IF:
                if stack.pop() == 0:
                    jump_addr = tok.block.end + 1
                    if jump_addr < len(tokens) and tokens[jump_addr].value == KEYWORD_ELSE:
                        i = jump_addr + 1
                    else:
                        i = jump_addr
                else:
                    i += 1
            elif tok.value == KEYWORD_ELSE:
                i = tok.block.end
            elif tok.value == KEYWORD_DO:
                i += 1
            elif tok.value == KEYWORD_WHILE:
                if stack.pop() == 0:
                    i += 1
                else:
                    i = tok.block.start
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
                           "    sub rbx, rax\n" + \
                           "    push rbx\n"
            elif tok.value == OP_EQ:
                buffer += f"    ;; EQ\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    mov rcx, 1\n" + \
                           "    mov rdx, 0\n" + \
                           "    cmp rax, rbx\n" + \
                           "    cmove rdx, rcx\n" + \
                           "    push rdx\n"
            elif tok.value == OP_LT:
                buffer += f"    ;; LT\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    mov rcx, 1\n" + \
                           "    mov rdx, 0\n" + \
                           "    cmp rbx, rax\n" + \
                           "    cmovl rdx, rcx\n" + \
                           "    push rdx\n"
            elif tok.value == OP_GT:
                buffer += f"    ;; GT\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    mov rcx, 1\n" + \
                           "    mov rdx, 0\n" + \
                           "    cmp rbx, rax\n" + \
                           "    cmovg rdx, rcx\n" + \
                           "    push rdx\n"
            elif tok.value == OP_DROP:
                buffer += f"    ;; DROP\n" + \
                           "    pop rax\n"
            elif tok.value == OP_SWAP:
                buffer += f"    ;; SWAP\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    push rax\n" + \
                           "    push rbx\n"
            elif tok.value == OP_DUP:
                buffer += f"    ;; DUP\n" + \
                           "    pop rax\n" + \
                           "    push rax\n" + \
                           "    push rax\n"
            elif tok.value == OP_OVER:
                buffer += f"    ;; OVER\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    push rbx\n" + \
                           "    push rax\n" + \
                           "    push rbx\n"
            elif tok.value == OP_ROT:
                buffer += f"    ;; ROT\n" + \
                           "    pop rax\n" + \
                           "    pop rbx\n" + \
                           "    pop rcx\n" + \
                           "    push rbx\n" + \
                           "    push rax\n" + \
                           "    push rcx\n"
            elif tok.value == OP_MEM:
                buffer += f"    ;; MEM\n" + \
                           "    push mem\n"
            elif tok.value == OP_READ:
                buffer += f"    ;; READ\n" + \
                           "    pop rax\n" + \
                           "    xor rbx, rbx\n" + \
                           "    mov bl, [rax]\n" + \
                           "    push rbx\n"
            elif tok.value == OP_WRITE:
                buffer += f"    ;; WRITE\n" + \
                           "    pop rbx\n" + \
                           "    pop rax\n" + \
                           "    mov [rax], bl\n"
        elif tok.type == TOKEN_KEYWORD:
            if tok.value == KEYWORD_IF:
                buffer += f"    ;; IF\n" + \
                          f"    pop rax\n" + \
                          f"    cmp rax, 0\n" + \
                          f"    je addr_{tok.block.end}\n"
            elif tok.value == KEYWORD_ELSE:
                buffer += f"    ;; ELSE\n" + \
                          f"    jmp addr_{tok.block.end}\n" + \
                          f"addr_{i}:\n"
            elif tok.value == KEYWORD_DO:
                buffer += f"    ;; DO\n" + \
                          f"do_{i}:\n"
            elif tok.value == KEYWORD_WHILE:
                buffer += f"    ;; WHILE\n" + \
                          f"    pop rax\n" + \
                          f"    cmp rax, 0\n" + \
                          f"    jne do_{tok.block.start}\n"
        elif tok.type == TOKEN_SPECIAL_CHAR:
            if tok.value == RCURLY:
                buffer += f"addr_{i}:\n"
        elif tok.type == TOKEN_INTRINSIC:
            buffer += f"    pop rdi\n" + \
                       "    call print\n"
        i += 1
    buffer += "    ;; RET\n" + \
        "    mov rax, 60\n" + \
        "    mov rdi, 0\n" + \
        "    syscall\n\n" + \
        "section .bss\n" + \
        "    mem: resb 1024\n"

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
