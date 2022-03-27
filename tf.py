#!/usr/bin/python

import sys
import subprocess
from typing import *

from token_types import *
from Token import *
from Parser import Parser

def find_block_end(tokens: List[Token]) -> List[Token]:
    stack: List[Token] = []
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
        elif tok.value == KEYWORD_FUNC:
            tok.block = Block(i, None)
            stack.append(tok)
        elif tok.value == RCURLY:
            if stack[-1].value == KEYWORD_FUNC:
                func: Token = stack[-1]
                tok.block = func.block
            elif stack[-1].value == KEYWORD_DO:
                continue
            stack[-1].block = Block(None, i)
            if i + 1 < len(tokens) and tokens[i + 1].value != KEYWORD_ELSE:
                stack.pop()
        elif tok.value == LPAREN:
            if tokens[i - 1].type == TOKEN_IDENTIFIER:
                func_id: Token = tokens[i - 1]
                if func_id.value == "main":
                    pass
                else:
                    i += 1
                    while i < len(tokens) and tokens[i].value != RPAREN:
                        if tokens[i].type == TOKEN_IDENTIFIER:
                            func_id.args += 1
                            i += 1
                        elif tokens[i].value == COMMA:
                            i += 1
        else:
            continue
    return tokens

op_table: List[str] = [
    # Token types
    "", "", "", "", "", "", "",

    # Operators
    "    pop rax\n    pop rbx\n    add rax, rbx\n    push rax\n",
    "    pop rax\n    pop rbx\n    sub rbx, rax\n    push rbx\n",
    "    pop rax\n    pop rbx\n    mov rcx, 1\n    mov rdx, 0\n    cmp rax, rbx\n    cmove rdx, rcx\n    push rdx\n",
    "    pop rax\n    pop rbx\n    mov rcx, 1\n    mov rdx, 0\n    cmp rbx, rax\n    cmovl rdx, rcx\n    push rdx\n",
    "    pop rax\n    pop rbx\n    mov rcx, 1\n    mov rdx, 0\n    cmp rbx, rax\n    cmovg rdx, rcx\n    push rdx\n",
    "    pop rax\n",
    "    pop rax\n    pop rbx\n    push rax\n    push rbx\n",
    "    pop rax\n    push rax\n    push rax\n",
    "    pop rax\n    pop rbx\n    push rbx\n    push rax\n    push rbx\n",
    "    pop rax\n    pop rbx\n    pop rcx\n    push rbx\n    push rax\n    push rcx\n",
    "    push mem\n",
    "    pop rax\n    xor rbx, rbx\n    mov bl, [rax]\n    push rbx\n",
    "    pop rbx\n    pop rax\n    mov [rax], bl\n",
    "    pop rcx\n    pop rax\n    shl rax, cl\n    push rax\n",
    "    pop rcx\n    pop rax\n    shr rax, cl\n    push rax\n",
    "    pop rax\n    xor rbx, rbx\n    mov rbx, [rax]\n    push rbx\n",
    "    pop rbx\n    pop rax\n    mov [rax], rbx\n",
]

syscall_table: List[str] = [
    "    pop rdi\n    pop rax\n    syscall\n",
    "    pop rsi\n    pop rdi\n    pop rax\n    syscall\n",
    "    pop rdx\n    pop rsi\n    pop rdi\n    pop rax\n    syscall\n",
    "    pop r10\n    pop rdx\n    pop rsi\n    pop rdi\n    pop rax\n    syscall\n",
    "    pop r8\n    pop r10\n    pop rdx\n    pop rsi\n    pop rdi\n    pop rax\n    syscall\n",
    "    pop r9\n    pop r8\n    pop r10\n    pop rdx\n    pop rsi\n    pop rdi\n    pop rax\n    syscall\n",
]

def generate_x86_64_nasm_linux(tokens: List[Token]) -> str:
    buffer: str = "section .text\n" + \
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
    "    ret\n"

    strings: List[Union[str, bytes, int]] = []
    identifiers: Dict[Union[str, bytes, int], Token] = {}
    local_vars: Dict[str, Dict[str, Union[int, str]]] = {}
    scope: str = "global"
    i: int = 0
    while i < len(tokens):
        tok: Token = tokens[i]
        if tok.type == TOKEN_NUMBER:
            buffer += f"    ;; PUSH {str(tok.value)}\n" + \
                      f"    push {str(tok.value)}\n"
        elif tok.type == TOKEN_OPEARTOR:
            buffer += op_table[tok.value]
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
            elif tok.value == KEYWORD_FUNC:
                next = tokens[i + 1]
                if next.type == TOKEN_IDENTIFIER:
                    identifiers[f"{str(next.value)}"] = tok
                    scope = str(next.value)
                    i += 1
                    buffer += f"{str(next.value)}:\n" + \
                              f"    push rbp\n" + \
                              f"    mov rbp, rsp\n"
                    arg_pass: int = 0
                    if tokens[i + 1].value != LPAREN:
                        sys.stdout.write("Expected ( after function name\n")
                        exit(1)
                    i += 1
                    local_vars[str(next.value)] = {}
                    while arg_pass < next.args:
                        i += 1
                        if tokens[i].type != TOKEN_IDENTIFIER:
                            sys.stdout.write("Expected name\n")
                            exit(1)
                        var_name = str(tokens[i].value)
                        local_vars[next.value][var_name] = next.args - arg_pass - 1
                        i += 1
                        if tokens[i].value not in {COMMA, RPAREN}:
                            assert False, "Expected `,` or `}`"
                        arg_pass += 1
                    i += 1
                else:
                    sys.stdout.write("Expected function name\n")
                    exit(1)
        elif tok.type == TOKEN_IDENTIFIER:
            if tok.value in identifiers and identifiers[tok.value].value == KEYWORD_FUNC:
                buffer += f"    call {str(tok.value)}\n"
            else:
                if scope in local_vars:
                    buffer += f"    mov rax, [rbp + {8 * local_vars[scope][str(tok.value)] + 16}]\n" + \
                               "    push rax\n"
        elif tok.type == TOKEN_SPECIAL_CHAR:
            if tok.value == RCURLY:
                if tok.block.start is not None and tokens[tok.block.start].value == KEYWORD_FUNC:
                    buffer += f"    pop rbp\n" + \
                              f"    ret\n"
                else:
                    buffer += f"addr_{i}:\n"
        elif tok.type == TOKEN_INTRINSIC:
            if tok.value == INTRINSIC_PRINT:
                buffer += f"    pop rdi\n" + \
                           "    call print\n"
            else:
                buffer += syscall_table[tok.value - 30]
        elif tok.type == TOKEN_STRING_LITERAL:
            buffer += f"    ;; STRING\n" + \
                      f"    push str_{len(strings)}\n"
            strings.append(tok.value)
        i += 1
    buffer += "_start:\n" + \
        "    call main\n" + \
        "    ;; RET\n" + \
        "    mov rax, 60\n" + \
        "    mov rdi, 0\n" + \
        "    syscall\n\n" + \
        "section .bss\n" + \
        "    mem: resb 1024\n" + \
        "section .data\n"

    for i, string in enumerate(strings):
        if isinstance(string, bytes):
            raw_byte: str = ','.join([hex(bytes(x, 'utf-8')[0]) for x in list(string.decode('unicode_escape'))])
            buffer += f"str_{i}:\n   db {raw_byte}\n"

    return buffer

def run_command(args: List[str]) -> None:
    buf: str = '>>> '
    for arg in args:
        buf += arg + " "

    sys.stdout.write(buf + "\n")
    subprocess.call(args)

def compile_program(tokens: List[Token], program_file: str) -> str:
    buffer: str = generate_x86_64_nasm_linux(tokens)
    out_filename: str = program_file.split('.')[0]

    with open(out_filename + ".asm", "w") as out:
        out.write(buffer)

    run_command(["nasm", "-felf64", out_filename + ".asm"])
    run_command(["ld", "-o", out_filename, out_filename + ".o"])

    return out_filename

def execute(flag: str, program_file: str) -> None:
    parser: Parser = Parser(program_file)
    tokens: List[Token] = list(parser.parse())
    tokens = find_block_end(tokens)

    if flag == "-r":
        exec_name: str = compile_program(tokens, program_file)
        run_command(["./" + exec_name])
    elif flag == "-c":
        compile_program(tokens, program_file)
    else:
        print(f"Unknown flag {flag}")
        exit(1)

def main(argv: List[str]) -> None:
    exec_name: str = argv[0]
    argv = argv[1:]
    if len(argv) < 2:
        sys.stdout.write(f"{exec_name}: not enough arguments\n")
        exit(1)

    file_path, exec_flag = argv[1], argv[0]
    execute(exec_flag, file_path)

if __name__ == "__main__":
    main(sys.argv)
