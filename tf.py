#!/usr/bin/python

import sys
import subprocess

from token_types import *
from Token import *
from Lexer import Lexer
from Parser import BinaryKind, IRKind, Parser

def generate_binary_op(op):
    match op[1]:
        case BinaryKind.ADD:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    add rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.SUB:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    sub rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.MUL:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    mul rbx\n" + \
            "    push rax\n"
        case BinaryKind.DIV:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    div rbx\n" + \
            "    push rax\n"
        case BinaryKind.LT:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    cmp rax, rbx\n" + \
            "    setl al\n" + \
            "    push rax\n"
        case BinaryKind.GT:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    cmp rax, rbx\n" + \
            "    setg al\n" + \
            "    push rax\n"
        case BinaryKind.SHL:
            return \
            "    pop rcx\n" + \
            "    pop rax\n" + \
            "    sal rax, cl\n" + \
            "    push rax\n"
        case BinaryKind.SHR:
            return \
            "    pop rcx\n" + \
            "    pop rax\n" + \
            "    sar rax, cl\n" + \
            "    push rax\n"
        case BinaryKind.AND:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    test rax, rax\n" + \
            "    setne al\n" + \
            "    test rbx, rbx\n" + \
            "    setne bl\n" + \
            "    and rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.OR:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    test rax, rax\n" + \
            "    setne al\n" + \
            "    test rbx, rbx\n" + \
            "    setne bl\n" + \
            "    or rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.EQ:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    cmp rax, rbx\n" + \
            "    sete al\n" + \
            "    push rax\n"

def generate_intrinsic(ir):
    syscall_stmts = [
    "    pop r9\n",
    "    pop r8\n",
    "    pop r10\n",
    "    pop rdx\n",
    "    pop rsi\n",
    "    pop rdi\n",
    "    pop rax\n",
    "    syscall\n",
    "    push rax\n",]
    match ir[1]:
        case 'print':
            return \
            "    pop rdi\n" + \
            "    call print\n"
        case 'syscall1':
            return \
                "".join(syscall_stmts[5:])
        case 'syscall2':
            return \
                "".join(syscall_stmts[4:])
        case 'syscall3':
            return \
                "".join(syscall_stmts[3:])
        case 'syscall4':
            return \
                "".join(syscall_stmts[2:])
        case 'syscall5':
            return \
                "".join(syscall_stmts[1:])
        case 'syscall6':
            return \
                "".join(syscall_stmts)
        case 'drop':
            return \
            "    pop rax\n"
        case 'swap':
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    push rax\n" + \
            "    push rbx\n"
        case 'dup':
            return \
            "    pop rax\n" + \
            "    push rax\n" + \
            "    push rax\n"
        case 'over':
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    push rbx\n" + \
            "    push rax\n" + \
            "    push rbx\n"
        case 'rot':
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    pop rcx\n" + \
            "    push rbx\n" + \
            "    push rax\n" + \
            "    push rcx\n"
        case 'mem':
            # TODO: remove this intrinsic?? because we can use mmap syscall
            # for memory allocation
            return \
            "    push mem\n"
        case 'read8':
            return \
            "    pop rax\n" + \
            "    xor rbx, rbx\n" + \
            "    mov bl, [rax]\n" + \
            "    push rbx\n"
        case 'write8':
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    mov [rax], bl\n"
        case 'read64':
            return \
            "    pop rax\n" + \
            "    xor rbx, rbx\n" + \
            "    mov rbx, [rax]\n" + \
            "    push rbx\n"
        case 'write64':
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    mov [rax], rbx\n"
        case 'divmod':
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    xor rdx, rdx\n" + \
            "    div rbx\n" + \
            "    push rax\n" + \
            "    push rdx\n"
        case _:
            print("Undefined intrinsic")
            exit(1)

def generate_body(ir):
    buffer = ""
    i = 0
    data = {
        'strings': [],
        'funcs': []
    }
    while i < len(ir):
        op = ir[i]
        if op[0] == IRKind.PushInt:
            buffer += f"    push {str(op[1])}\n"
        elif op[0] == IRKind.PushStr:
            buffer += f"    push S{len(data['strings'])}\n"
            data['strings'].append(op[1])
        elif op[0] == IRKind.Binary:
            buffer += generate_binary_op(op)
        elif op[0] == IRKind.Func:
            buffer += f"{op[1]}:\n" + \
                "    push rbp\n" + \
                "    mov rbp, rsp\n"
            buf, tmp_data = generate_body(op[3])
            buffer += buf
            data['strings'] += tmp_data['strings']
            data['funcs'].append(op[1])
            buffer += "    pop rbp\n    ret\n"
        elif op[0] == IRKind.Intrinsic:
            buffer += generate_intrinsic(op)
        elif op[0] == IRKind.Call:
            # TODO: this is just a hack atm but push rax just in case
            # we want the return value and there's no other way to get
            # that, return statements will fix this issue but for now
            # this will do
            buffer += f"    call {op[1]}\n    push rax\n"
        i += 1
    return buffer, data

def generate_x86_64_nasm_linux(ir):
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
    "    ret\n"

    buf, data = generate_body(ir)
    buffer += buf
    buffer += "_start:\n" + \
        "    call main\n" + \
        "    mov rax, 60\n" + \
        "    mov rdi, 0\n" + \
        "    syscall\n\n" + \
        "section .bss\n" + \
        "    mem: resb 1024\n" + \
        "section .data\n"

    for i, string in enumerate(data['strings']):
        if isinstance(string, bytes):
            raw_byte: str = ','.join([hex(bytes(x, 'utf-8')[0]) for x in list(string.decode('unicode_escape'))])
            buffer += f"S{i}:\n   db {raw_byte}\n"

    return buffer

def run_command(args):
    buf = '>>> '
    for arg in args:
        buf += arg + " "

    sys.stdout.write(buf + "\n")
    subprocess.call(args)

def compile_program(ir, program_file):
    buffer = generate_x86_64_nasm_linux(ir)
    out_filename = program_file.split('.')[0]

    with open(out_filename + ".asm", "w") as out:
        out.write(buffer)

    run_command(["nasm", "-felf64", out_filename + ".asm"])
    run_command(["ld", "-o", out_filename, out_filename + ".o"])

    return out_filename

def execute(flag, program_file):
    lexer = Lexer(program_file)
    tokens = list(lexer.lex())
    parser = Parser(program_file, tokens)
    ir = list(parser.parse())

    if flag == "-r":
        exec_name = compile_program(ir, program_file)
        run_command(["./" + exec_name])
    elif flag == "-c":
        compile_program(ir, program_file)
    else:
        print(f"Unknown flag {flag}")
        exit(1)

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
