#!/usr/bin/python

import os
import copy
from pathlib import Path
import sys
import subprocess
from dataclasses import dataclass
from gen.gen import Gen

from token_types import *
from Token import *
from Lexer import Lexer
from Parser import *
from Ast import *

offset = 0
arg_regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]

class Backend(Enum):
    Nasm = auto()
    Native = auto()

@dataclass
class State:
    compiler_src_path = Path(__file__).parent.parent
    libpath = os.path.join(compiler_src_path, "library")
    root = None # root is known after src file is provided to the compiler for compilation
    filepath = ""
    backend = Backend.Nasm
    link_libc = False

print_intrinsic = \
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

def generate_binary_op(op):
    match op.kind:
        case BinaryKind.ADD:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rax\n" + \
                "    pop rbx\n" + \
                "    add rax, rbx\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rax\n" + \
                "    pop rbx\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    addsd xmm0, xmm1\n" + \
                "    movq rax, xmm0\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
        case BinaryKind.SUB:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    sub rax, rbx\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    subsd xmm0, xmm1\n" + \
                "    movq rax, xmm0\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
        case BinaryKind.MUL:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rax\n" + \
                "    pop rbx\n" + \
                "    imul rax, rbx\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rax\n" + \
                "    pop rbx\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    mulsd xmm0, xmm1\n" + \
                "    movq rax, xmm0\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
        case BinaryKind.DIV:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    cqo\n" + \
                "    idiv rbx\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    divsd xmm0, xmm1\n" + \
                "    movq rax, xmm0\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
        case BinaryKind.LT:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    sub rbx, 1\n" + \
                "    cmp rax, rbx\n" + \
                "    mov rax, 0\n" + \
                "    setle al\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rax\n" + \
                "    pop rbx\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    comisd xmm0, xmm1\n" + \
                "    mov rax, 0\n" + \
                "    seta al\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
        case BinaryKind.GT:
            if op.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    cmp rax, rbx\n" + \
                "    mov rax, 0\n" + \
                "    setg al\n" + \
                "    push rax\n"
            elif op.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rbx\n" + \
                "    pop rax\n" + \
                "    movq xmm0, rax\n" + \
                "    movq xmm1, rbx\n" + \
                "    comisd xmm0, xmm1\n" + \
                "    mov rax, 0\n" + \
                "    seta al\n" + \
                "    push rax\n"
            else:
                print(f"Unreachable in `generate_binary_op`, OP: {op.kind}, TYPE: {op.ty}")
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
            "    mov rax, 0\n" + \
            "    sete al\n" + \
            "    push rax\n"
        case BinaryKind.NOTEQ:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    cmp rax, rbx\n" + \
            "    mov rax, 0\n" + \
            "    setne al\n" + \
            "    push rax\n"
        case BinaryKind.MOD:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    xor rdx, rdx\n" + \
            "    idiv rbx\n" + \
            "    push rdx\n"
        case _:
            print("Unexpected binary-op")
            exit(1)

def generate_intrinsic(ir):
    match ir.kind:
        case IntrinsicKind.PRINT:
            return \
            "    pop rdi\n" + \
            "    call print\n"
        case IntrinsicKind.SYSCALL:
            return \
            "    pop rax\n" + \
            "    syscall\n" + \
            "    push rax\n"
        case IntrinsicKind.DROP:
            return \
            "    lea rsp, [rsp + 8]\n"
        case IntrinsicKind.SWAP:
            return \
            "    pop rax\n" + \
            "    push QWORD [rsp]\n" + \
            "    mov [rsp + 8], rax\n"
        case IntrinsicKind.DUP:
            return \
            "    push QWORD [rsp]\n"
        case IntrinsicKind.OVER:
            return \
            "    push QWORD [rsp + 8]\n"
        case IntrinsicKind.ROT:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    pop rcx\n" + \
            "    push rbx\n" + \
            "    push rax\n" + \
            "    push rcx\n"
        case IntrinsicKind.MEM:
            # TODO: remove this intrinsic?? because we can use mmap syscall
            # for memory allocation
            return \
            "    push mem\n"
        case IntrinsicKind.CAST_INT:
            if ir.ty in {TypeKind.F32, TypeKind.F64}:
                return \
                "    pop rax\n" + \
                "    movq xmm0, rax\n" + \
                "    cvttsd2si rax, xmm0\n" + \
                "    push rax\n"
            return ""
        case IntrinsicKind.CAST_STR:
            return ""
        case IntrinsicKind.CAST_FLOAT:
            if ir.ty in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64}:
                return \
                "    pop rax\n" + \
                "    pxor xmm0, xmm0\n" + \
                "    cvtsi2sd xmm0, rax\n" + \
                "    movq rax, xmm0\n" + \
                "    push rax\n"
            return ""
        case IntrinsicKind.READ8:
            return \
            "    pop rax\n" + \
            "    xor rbx, rbx\n" + \
            "    mov bl, [rax]\n" + \
            "    push rbx\n"
        case IntrinsicKind.WRITE8:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    mov [rax], bl\n"
        case IntrinsicKind.READ64:
            return \
            "    pop rax\n" + \
            "    xor rbx, rbx\n" + \
            "    mov rbx, [rax]\n" + \
            "    push rbx\n"
        case IntrinsicKind.WRITE64:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    mov [rax], rbx\n"
        case IntrinsicKind.DIVMOD:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    xor rdx, rdx\n" + \
            "    div rbx\n" + \
            "    push rax\n" + \
            "    push rdx\n"
        case IntrinsicKind.HERE:
            assert False, "this should be unreachable"
        case IntrinsicKind.FSQRT:
            return \
            "    pop rax\n" + \
            "    movq xmm0, rax\n" + \
            "    sqrtsd xmm0, xmm0\n" + \
            "    movq rax, xmm0\n" + \
            "    push rax\n"
        case _:
            print("Undefined intrinsic")
            exit(1)

def find_var(data, var):
    size = len(data)
    for i in reversed(range(size)):
        for d in data[i]:
            if var == d['sym']:
                return d['offset']

    # TODO: also report the location of error in source code
    print(f"`{var}` is not defined")
    exit(1)

def generate_body(ir, data):
    def find_str(str_to_find):
        for s, str_addr in data['strings']:
            if str_to_find == s:
                return str_addr

    global offset
    data['scopes'].append([])
    buffer = ""
    i = 0
    while i < len(ir):
        op = ir[i]
        match op:
            case PushInt():
                buffer += f"    push {op.value}\n"
            case PushFloat():
                buffer += f"    movsd xmm0, [flt{op.addr}]\n" + \
                    "    movq rax, xmm0\n" + \
                    "    push rax\n"
                data['floats'].append([op.value, op.addr])
            case PushStr():
                if addr := find_str(op.value):
                    buffer += f"    push S{addr}\n"
                else:
                    buffer += f"    push S{op.addr}\n"
                    data['strings'].append([op.value, op.addr])
            case PushBool():
                val = 1 if op.value == 'true' else 0
                buffer += f"    mov BYTE al, {val}\n" + \
                    "    push rax\n"
            case PushVar():
                off = find_var(data['scopes'], op.name)
                buffer += f"    push QWORD [rbp - {off}]\n"
            case PushAddr():
                off = find_var(data['scopes'], op.name)
                buffer += f"    lea rax, [rbp - {off}]\n" + \
                    "    push rax\n"
            case Binary():
                buffer += generate_binary_op(op)
            case Fn():
                data['funcs'][op.name] = op.sig
                if op.extern:
                    buffer += f"extern {op.name}\n"
                    i += 1
                    continue
                offset = 0
                local_var_count = op.sig.locals
                buffer += f"{op.name}:\n" + \
                    "    push rbp\n" + \
                    "    mov rbp, rsp\n" + \
                    "    sub rsp, {}\n".format(local_var_count * 8)
                nargs = len(op.sig.args)
                regs = arg_regs[:nargs]
                for reg in regs:
                    buffer += f"    push {reg}\n"
                buf, data = generate_body(op.body, data)
                buffer += buf
                # TODO: use `leave` here and in Return
                if not op.sig.ret_ty:
                    buffer += \
                    "    add rsp, {}\n".format(local_var_count * 8) + \
                    "    pop rbp\n" + \
                    "    ret\n"
            case Intrinsic():
                if op.kind == IntrinsicKind.HERE:
                    buffer += \
                    f"    push __here{len(data['locs'])}\n"
                    data['locs'].append(op.loc)
                else:
                    buffer += generate_intrinsic(op)
            case Call():
                signature = data['funcs'][op.name]
                nargs = len(signature.args)
                regs = arg_regs[:nargs]
                for x in reversed(regs):
                    buffer += f"    pop {x}\n"
                if float_args := len([arg for arg in signature.args if arg in [TypeKind.F64, TypeKind.F32]]):
                    buffer += f"    mov rax, {float_args}\n"
                buffer += f"    call {op.name}\n"
                if signature.ret_ty:
                    buffer += "    push rax\n"
            case Deref():
                off = find_var(data['scopes'], op.name)
                match op.ty:
                    case TypeKind.I8 | TypeKind.I16 | TypeKind.I32 | TypeKind.I64 | TypeKind.F32 | TypeKind.F64 | TypeKind.STR | TypeKind.BOOL:
                        buffer += f"    mov rax, [rbp - {off}]\n    push QWORD [rax]\n"
                    case _:
                        assert False, f"{op.ty} is not defined"
            case If():
                buffer += \
                "    pop rax\n" + \
                "    cmp rax, 0\n" + \
                "    je ADDR{}\n".format(op.addr)
                buf, data = generate_body(op.body, data)
                buffer += buf
                if op.else_body:
                    buffer += f"    jmp ADDR{op.else_addr}\nADDR{op.addr}:\n"
                    buf, data = generate_body(op.else_body, data)
                    buffer += buf
                    buffer += f"ADDR{op.else_addr}:\n"
                else:
                    buffer += f"ADDR{op.addr}:\n"
            case While():
                buffer += \
                f"ADDR{op.addr}:\n"
            case Do():
                buffer += \
                "    pop rax\n" + \
                "    cmp rax, 0\n" + \
                "    je ADDR{}\n".format(op.end_addr)
                buf, data = generate_body(op.body, data)
                buffer += buf
                buffer += f"    jmp ADDR{op.do_addr}\nADDR{op.end_addr}:\n"
            case Destruct():
                for reg in reversed(arg_regs[:int(op.value)]):
                    buffer += f"    pop {reg}\n"
            case Let():
                reg = arg_regs[:len(op.symbols)]
                for x, v in enumerate(op.symbols):
                    offset += 8
                    data['scopes'][-1].append({'sym': v, 'offset': offset})
                    buffer += f"    pop {reg[x]}\n    mov [rbp - {offset}], {reg[x]}\n"
            case Return():
                # TODO: use `leave` if it's possible
                buffer += \
                "    pop rax\n" + \
                "    add rsp, {}\n".format(op.locals * 8) + \
                "    pop rbp\n" + \
                "    ret\n"
                break
            case Const() | Macro() | Import():
                pass
            case _:
                assert False, f"{op}"
        i += 1
    data['scopes'].pop()
    return buffer, data


def emit_data_section(data):
    buffer = ""
    for string, i in data['strings']:
        if isinstance(string, bytes):
            raw_byte: str = ','.join([hex(bytes(x, 'utf-8')[0]) for x in list(string.decode('unicode_escape'))])
            buffer += f"S{i}:\n    db {raw_byte},0x0\n"
    for flt, i in data['floats']:
        buffer += f"flt{i}:\n    dq {flt}\n"
    for i, h in enumerate(data['locs']):
        buffer += f"__here{i}:\n    dq {h[0] + 1}\n    dq {h[1] + 1}\n"
    return buffer


def generate_x86_64_gcc_linux(ir):
    buffer = "section .text\n" + \
    "global main\n" + \
    print_intrinsic

    data = {
        'strings': [],
        'floats': [],
        'funcs': {},
        'scopes': [],
        'locs': [],
    }
    buf, data = generate_body(ir, data)
    buffer += buf
    buffer += "section .bss\n" + \
        "    mem: resb 1024\n" + \
        "section .data\n"
    buffer += emit_data_section(data)

    return buffer

def generate_x86_64_nasm_linux(ir):
    buffer = "section .text\n" + \
    "global _start\n" + \
    print_intrinsic

    data = {
        'strings': [],
        'floats': [],
        'funcs': {},
        'scopes': [],
        'locs': [],
    }
    buf, data = generate_body(ir, data)
    buffer += buf
    buffer += "_start:\n" + \
        "    mov rdi, rsp\n" + \
        "    call main\n" + \
        "    mov rax, 60\n" + \
        "    mov rdi, 0\n" + \
        "    syscall\n\n" + \
        "section .bss\n" + \
        "    mem: resb 1024\n" + \
        "section .data\n"
    buffer += emit_data_section(data)

    return buffer

# TODO: find a better solution for handling imports
# maybe something like path segments eg.`linux::write` would be nice
def resolve_imports(ir, addr):
    i = 0
    for op in ir[:]:
        match op:
            case Import():
                module = op.name
                path = Path(State.root).parent
                mod_path = os.path.join(path, module) + ".tf"
                # if not found then look for the module in standard library
                if Path(State.root).stem == module or not Path(mod_path).exists():
                    mod_path = os.path.join(State.libpath, module) + ".tf"
                    # if the file is still not found then it doesn't exist
                    if not Path(mod_path).exists():
                        print(f"tf: module `{module}` doesn't exist")
                        exit(1)
                tokens = list(Lexer(mod_path).lex())
                parser = Parser(mod_path, tokens)
                parser.addr = addr
                mod_ir = list(parser.parse())
                addr += parser.addr
                ir.pop(i)
                ir = ir[:i] + mod_ir + ir[i:]
                i += len(mod_ir) - 1
        i += 1
    return ir

def emit_error(msg, node):
    loc = node.loc
    loc = [loc[0] + 1, loc[1] + 1]
    print(f"{loc}: {msg}")
    exit(1)

def check_var_redefenitions(node, data):
    for d in data['scopes'][-1]:
        if d['sym'] in node.symbols:
            emit_error(f"`{d['sym']}` is already defined", node)

def check_stack_underflow(stack, node):
    if not stack:
        emit_error("STACK UNDERFLOW: attempt to pop from an empty stack", node)

def pop_without_underflow(stack, node):
    check_stack_underflow(stack, node)
    last = stack.pop()
    return stack, last

def find_func(node, data):
    for fn in data:
        if node.name == fn['sym']:
            return fn

    emit_error(f"`{node.name}` is not defined", node)

def check_binary_op(node, stack, expected):
    stack, rhs = pop_without_underflow(stack, node)
    stack, lhs = pop_without_underflow(stack, node)
    if node.kind in [BinaryKind.SHL, BinaryKind.SHR, BinaryKind.MOD] and (TypeKind.F32 in [lhs, rhs] or TypeKind.F64 in [lhs, rhs]):
        emit_error(f"expected `int` but got `float`", node)
    if lhs not in expected or rhs not in expected:
        emit_error(f"expected {expected} for {node.kind} but got `{lhs}` and `{rhs}`", node)
    return stack, [lhs, rhs]

def type_chk(ir, data, new_scope=False):
    if new_scope:
        data['scopes'].append([])
    stack = data['stack']

    for id, node in enumerate(ir):
        match node:
            case PushInt():
                stack.append(TypeKind.I64)
            case PushFloat():
                stack.append(TypeKind.F64)
            case PushStr():
                stack.append(TypeKind.STR)
            case PushBool():
                stack.append(TypeKind.BOOL)
            case PushVar():
                typ = None
                for i in reversed(range(len(data['scopes']))):
                    for d in data['scopes'][i]:
                        if node.name == d['sym']:
                            typ = d['type']
                            break
                if typ != None:
                    stack.append(typ)
                else:
                    emit_error(f"`{node.name}` is not defined", node)
            case PushAddr():
                # TODO: man just introduce a usize or something
                typ = None
                for i in reversed(range(len(data['scopes']))):
                    for d in data['scopes'][i]:
                        if node.name == d['sym']:
                            typ = d['type']
                            break
                if typ != None:
                    stack.append(typ)
                else:
                    emit_error(f"`{node.name}` is not defined", node)
            case Binary():
                if node.kind in [BinaryKind.ADD, BinaryKind.SUB, BinaryKind.MUL, BinaryKind.DIV, BinaryKind.SHL, BinaryKind.SHR, BinaryKind.MOD]:
                    stack, operands = check_binary_op(node, stack, {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64, TypeKind.F32, TypeKind.F64})
                    ir[id].ty = operands[0]
                    stack.append(operands[0])
                elif node.kind in [BinaryKind.LT, BinaryKind.GT]:
                    stack, operands = check_binary_op(node, stack, {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64, TypeKind.F32, TypeKind.F64})
                    ir[id].ty = operands[0]
                    stack.append(TypeKind.BOOL)
                elif node.kind in [BinaryKind.AND, BinaryKind.OR]:
                    stack, operands = check_binary_op(node, stack, {TypeKind.BOOL})
                    stack.append(TypeKind.BOOL)
                elif node.kind in [BinaryKind.EQ, BinaryKind.NOTEQ]:
                    stack, operands = check_binary_op(node, stack, {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64, TypeKind.BOOL})
                    stack.append(TypeKind.BOOL)
                else:
                    emit_error(f"Unexpected binary-op `{node.kind}`", node)
            case Fn():
                sig = node.sig
                data['func_scope'] = node.name
                if type(sig) != FnSig:
                    emit_error(f"`{node.name}` does not have a proper signature", node)
                if not node.extern:
                    for typ in sig.args:
                        stack.append(typ)
                data['funcs'].append({'sym': node.name, 'sig': sig})
                if sig.ret_ty:
                    if not sig.has_ret and not node.extern:
                        emit_error(f"`{node.name}` expects to return `{sig.ret_ty}` but no return statement found", node)
                if node.extern:
                    continue
                data = type_chk(node.body, data, True)
                node.sig.locals = data['locals']
                data['locals'] = 0
                stack = data['stack']
                unhandled_stack_error(stack, node, f"Unhandled data in `{data['func_scope']}()`, consider dropping {len(stack)} {value_or_values(stack)}")
            case Intrinsic():
                if node.kind == IntrinsicKind.PRINT:
                    stack, typ = pop_without_underflow(stack, node)
                    if typ not in {TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64, TypeKind.F32, TypeKind.F64, TypeKind.BOOL, TypeKind.STR}:
                        emit_error(f"`{node.kind}` expects an `int`, `bool`, `float`, `str` but `{typ}` was given", node)
                elif node.kind == IntrinsicKind.SYSCALL:
                    stack, typ = pop_without_underflow(stack, node)
                    if typ not in {TypeKind.I64}:
                        emit_error(f"`{node.kind}` expects an `int` but `{typ}` was given", node)
                    stack.append(TypeKind.I64)
                elif node.kind == IntrinsicKind.DROP:
                    stack, _ = pop_without_underflow(stack, node)
                elif node.kind == IntrinsicKind.SWAP:
                    stack, lhs = pop_without_underflow(stack, node)
                    stack, rhs = pop_without_underflow(stack, node)
                    stack += [lhs, rhs]
                elif node.kind == IntrinsicKind.DUP:
                    stack, typ = pop_without_underflow(stack, node)
                    stack += [typ, typ]
                elif node.kind == IntrinsicKind.OVER:
                    stack, lhs = pop_without_underflow(stack, node)
                    stack, rhs = pop_without_underflow(stack, node)
                    stack += [rhs, lhs, rhs]
                elif node.kind == IntrinsicKind.ROT:
                    stack, one = pop_without_underflow(stack, node)
                    stack, two = pop_without_underflow(stack, node)
                    stack, three = pop_without_underflow(stack, node)
                    stack += [two, one, three]
                elif node.kind == IntrinsicKind.MEM:
                    stack.append(TypeKind.I64)
                elif node.kind == IntrinsicKind.CAST_INT:
                    stack, typ = pop_without_underflow(stack, node)
                    ir[id].ty = typ
                    stack.append(TypeKind.I64)
                elif node.kind == IntrinsicKind.CAST_STR:
                    stack, typ = pop_without_underflow(stack, node)
                    stack.append(TypeKind.STR)
                elif node.kind == IntrinsicKind.CAST_FLOAT:
                    stack, typ = pop_without_underflow(stack, node)
                    ir[id].ty = typ
                    stack.append(TypeKind.F64)
                elif node.kind == IntrinsicKind.READ8:
                    stack, addr = pop_without_underflow(stack, node)
                    if addr != TypeKind.I64:
                        emit_error(f"Cannot read `{addr}`", node)
                    stack.append(TypeKind.I8)
                elif node.kind == IntrinsicKind.WRITE8:
                    stack, val = pop_without_underflow(stack, node)
                    if val not in [TypeKind.I8, TypeKind.I16, TypeKind.I32, TypeKind.I64]:
                        emit_error(f"Expected `int` but got `{val}`", node)
                    stack, addr = pop_without_underflow(stack, node)
                    if addr != TypeKind.I64:
                        emit_error(f"Cannot write to `{addr}`", node)
                elif node.kind == IntrinsicKind.READ64:
                    stack, addr = pop_without_underflow(stack, node)
                    if addr not in {TypeKind.STR, TypeKind.I64}:
                        emit_error(f"Cannot read `{addr}`", node)
                    stack.append(TypeKind.I64)
                elif node.kind == IntrinsicKind.WRITE64:
                    stack, val = pop_without_underflow(stack, node)
                    if val not in {TypeKind.I64, TypeKind.F64}:
                        emit_error(f"Expected `int` or `float` but got `{val}`", node)
                    stack, addr = pop_without_underflow(stack, node)
                    if addr not in {TypeKind.I64}:
                        emit_error(f"Cannot write to `{addr}`", node)
                elif node.kind == IntrinsicKind.DIVMOD:
                    assert False, "TODO: remove this intrinsic and add a separate `mod` binary-op"
                elif node.kind == IntrinsicKind.HERE:
                    stack.append(TypeKind.I64)
                elif node.kind == IntrinsicKind.FSQRT:
                    stack, val = pop_without_underflow(stack, node)
                    if val not in {TypeKind.F32, TypeKind.F64}:
                        emit_error(f"Expected `float` but got `{val}`", node)
                    stack.append(TypeKind.F64)
                else:
                    assert False, f"Undefined intrinsic {node.kind}"
            case Call():
                fn = find_func(node, data['funcs'])
                sig = fn['sig']
                vars = stack[-len(sig.args):]
                from beeprint import pp
                if len(vars) != len(sig.args):
                    emit_error(f"`{fn['sym']}` Expected {len(sig.args)} args but got {len(vars)}", node)

                for exp_typ, real_typ in zip(sig.args, vars):
                    if real_typ != exp_typ:
                        emit_error(f"`{fn['sym']}` Expected {exp_typ} but got {real_typ}", node)
                stack = stack[:-len(sig.args)]
                if sig.ret_ty:
                    stack.append(sig.ret_ty)
            case Deref():
                typ = None
                for i in reversed(range(len(data['scopes']))):
                    for d in data['scopes'][i]:
                        if node.name == d['sym']:
                            typ = d['type']
                            break
                if typ != None:
                    ir[id].ty = typ
                    stack.append(typ)
                else:
                    emit_error(f"`{node.name}` is not defined", node)
            case If():
                stack, cond = pop_without_underflow(stack, node)
                if cond != TypeKind.BOOL:
                    emit_error(f"`if` expects a `bool` but found `{cond}`", node)
                stack_snap = stack[:]
                data = type_chk(node.body, data, new_scope=True)
                if not node.else_body:
                    if data['stack'] != stack_snap:
                        unhandled_stack_error(stack, node, f"`if` block modifies the stack, consider dropping {len(stack)} {value_or_values(stack)} or adding an `else` block with same stack order")
                else:
                    data['stack'] = stack_snap
                    stack_snap2 = stack[:]
                    data = type_chk(node.else_body, data)
                    if stack_snap2 != stack_snap:
                        print("`if`:", stack_snap)
                        print("`else`:", stack_snap2)
                        emit_error(f"`else` has different stack order then `if`", node.else_body.loc)
            case Do():
                stack, cond = pop_without_underflow(stack, node)
                if cond != TypeKind.BOOL:
                    emit_error(f"`do` expects a `bool` but found `{cond}`", node)
                data = type_chk(node.body, data, new_scope=True)
                stack = data['stack']
            case Destruct():
                for val in range(int(node.value)):
                    stack, typ = pop_without_underflow(stack, node)
            case Let():
                check_var_redefenitions(node, data)
                for sym in reversed(node.symbols):
                    data['locals'] += 1
                    stack, typ = pop_without_underflow(stack, node)
                    data['scopes'][-1].append({'sym': sym, 'type': typ})
            case Return():
                sig = None
                for fn in data['funcs']:
                    if data['func_scope'] == fn['sym']:
                        sig = fn['sig']
                if not sig:
                    emit_error(f"function `{data['func_scope']}` is not defined?", node)

                ir[id].locals = data['locals']
                stack, typ = pop_without_underflow(stack, node)
                if sig.ret_ty and not sig.has_ret:
                    emit_error(f"No return type specified for func `{data['func_scope']}` but it returns `{typ}`", node)
                elif sig.has_ret and sig.ret_ty:
                    if typ != sig.ret_ty:
                        emit_error(f"func `{data['func_scope']}` returns `{typ}` but expected `{sig[2]}`", node)

    if new_scope:
        data['scopes'].pop()
    data['stack'] = stack
    return data

def value_or_values(stack):
    if len(stack) == 1:
        return "value"
    else:
        return "values"

def unhandled_stack_error(stack, node, msg):
    if stack:
        emit_error(msg, node)

def dump_ir(ir, level):
    for x in ir:
        match x:
            case Fn():
                sys.stdout.write("    "*level)
                print(f"func {x.name}")
                dump_ir(x.body, level + 1)
            case Do():
                sys.stdout.write("    "*level)
                print("do:")
                dump_ir(x.body, level + 1)
            case If():
                sys.stdout.write("    "*level)
                print("if:")
                dump_ir(x.body, level + 1)
                if x.else_body:
                    sys.stdout.write("    "*level)
                    print("else:")
                    dump_ir(x.else_body, level + 1)
            case Macro():
                sys.stdout.write("    "*level)
                print(f"macro {x.name}")
                dump_ir(x.tokens, level + 1)
            case _:
                sys.stdout.write("    "*level)
                print(x)

def ir_passes(ir, addr):
    data = {}
    data['consts'] = {}
    ir = resolve_imports(ir, addr)
    ir, _ = expand_const(ir, data)
    data['macros'] = {}
    ir, _ = expand_macros(ir, data)
    data = { 'scopes': [], 'funcs': [], 'stack': [], 'func_scope': 'global', 'locals': 0 }
    data = type_chk(ir, data)
    if data['stack']:
        print("Unhandled data on the stack")
    return ir

def expand_macros(ir, data):
    id = 0
    for node in ir[:]:
        match node:
            case Macro():
                data['macros'][node.name] = node.tokens
            case MacroCall():
                if node.name not in data['macros']:
                    print(f"macro `{node.name}` is not defined")
                    exit(1)
                ir.pop(id)
                body = copy.deepcopy(data['macros'][node.name])
                body, data = expand_macros(body, data)
                for i in range(len(body)):
                    body[i].loc = node.loc
                ir = ir[:id] + body + ir[id:]
                id += len(body) - 1
            case Fn():
                if node.body:
                    node.body, data = expand_macros(node.body, data)
            case If():
                node.body, data = expand_macros(node.body, data)
                if node.else_body:
                    node.else_body, data = expand_macros(node.else_body, data)
            case Do():
                node.body, data = expand_macros(node.body, data)
        id += 1
    return ir, data

def expand_const(ir, data):
    for i, op in enumerate(ir):
        match op:
            case Const():
                name = op.name
                if name in data['consts']:
                    print(f"constant `{name}` is already defined")
                    exit(1)
                data['consts'][name] = {
                    'type': op.typ,
                    'value': op.value
                }
            case Fn():
                if op.name in data['consts']:
                    print(f"`{op.name}` is already defined as a constant")
                    exit(1)
                if op.body:
                    op.body, data = expand_const(op.body, data)
            case Let():
                for sym in op.symbols:
                    if sym in data['consts']:
                        print(f"`{sym}` is already defined as a constant")
                        exit(1)
            case PushVar():
                if op.name in data['consts']:
                    lit = data['consts'][op.name]
                    if lit['type'] == LiteralKind.INT:
                        ir[i] = PushInt(lit['value'], [0, 0])
                    elif lit['type'] == LiteralKind.STR:
                        ir[i] = PushStr(lit['value'], [0, 0])
            case If():
                op.body, data = expand_const(op.body, data)
                if op.else_body:
                    op.else_body, data = expand_const(op.else_body, data)
            case Do():
                op.body, data = expand_const(op.body, data)
            case Macro():
                op.tokens, data = expand_const(op.tokens, data)

    return ir, data

def run_command(args):
    buf = '>>> '
    for arg in args:
        buf += arg + " "

    sys.stdout.write(buf + "\n")
    proc = subprocess.Popen(args)
    proc.communicate()
    if proc.returncode != 0:
        exit(proc.returncode)

def compile_program(ir, program_file):
    out_filename = os.path.join(program_file.parent, program_file.stem)

    if State.backend == Backend.Nasm:
        if State.link_libc:
            buffer = generate_x86_64_gcc_linux(ir)
        else:
            buffer = generate_x86_64_nasm_linux(ir)
        with open(out_filename + ".asm", "w") as out:
            out.write(buffer)
        # run_command(["nasm", "-felf64", "-g", "-F", "dwarf", out_filename + ".asm"])
        run_command(["nasm", "-felf64", out_filename + ".asm"])
        if State.link_libc:
            run_command(["gcc", "-o", out_filename, out_filename + ".o"])
        else:
            run_command(["ld", "-o", out_filename, out_filename + ".o"])
    elif State.backend == Backend.Native:
        gen = Gen(out_filename)
        gen.gen_exec(ir)

    return out_filename

def execute():
    program_file = State.filepath
    filepath = Path(program_file).absolute()
    if not filepath.exists():
        print(f"tf: `{program_file}` doesn't exist")
        exit(1)
    State.root = filepath
    lexer = Lexer(filepath)
    tokens = list(lexer.lex())
    parser = Parser(filepath, tokens)
    ir = list(parser.parse())
    ir = ir_passes(ir, parser.addr)
    compile_program(ir, filepath)

def parse_flag(flag, argv):
    match flag:
        case "-c":
            filepath, argv = lsplit(argv)
            State.filepath = filepath
        case "-be":
            be, argv = lsplit(argv)
            if be == "nasm":
                State.backend = Backend.Nasm
            elif be == "native":
                State.backend = Backend.Native
        case "--link-libc":
            State.link_libc = True
        case _:
            print(f"Unknown flag \"{flag}\"")
            exit(1)
    return argv

def lsplit(l):
    if l:
        return l[0], l[1:]
    else:
        print("not enough arguments")
        exit(1)

def main(argv):
    exec_name = argv[0]
    argv = argv[1:]
    if len(argv) < 2:
        sys.stdout.write(f"{exec_name}: not enough arguments\n")
        exit(1)

    while argv:
        flag, argv = lsplit(argv)
        argv = parse_flag(flag, argv)

    execute()

if __name__ == "__main__":
    main(sys.argv)
