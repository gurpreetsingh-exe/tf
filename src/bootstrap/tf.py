#!/usr/bin/python

import os
from pathlib import Path
import sys
import subprocess

from .token_types import *
from .Token import *
from .Lexer import Lexer
from .Parser import BinaryKind, IRKind, Parser

offset = 0
arg_regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
compiler_src_path = Path(__file__).parent.parent
libpath = os.path.join(compiler_src_path, "library")
root = None # root is known after src file is provided to the compiler for compilation

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
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    sub rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.MUL:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    imul rax, rbx\n" + \
            "    push rax\n"
        case BinaryKind.DIV:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    cdq\n" + \
            "    idiv rbx\n" + \
            "    push rax\n"
        case BinaryKind.LT:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    sub rbx, 1\n" + \
            "    cmp rax, rbx\n" + \
            "    mov rax, 0\n" + \
            "    setle al\n" + \
            "    push rax\n"
        case BinaryKind.GT:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    cmp rax, rbx\n" + \
            "    mov rax, 0\n" + \
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
        case BinaryKind.NOTEQ:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    cmp rax, rbx\n" + \
            "    setne al\n" + \
            "    push rax\n"
        case BinaryKind.MOD:
            return \
            "    pop rbx\n" + \
            "    pop rax\n" + \
            "    xor rdx, rdx\n" + \
            "    cdq\n" + \
            "    idiv rbx\n" + \
            "    push rdx\n"
        case _:
            print("Unexpected binary-op")
            exit(1)

def generate_intrinsic(ir):
    match ir[1]:
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
            "    pop rax\n"
        case IntrinsicKind.SWAP:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    push rax\n" + \
            "    push rbx\n"
        case IntrinsicKind.DUP:
            return \
            "    pop rax\n" + \
            "    push rax\n" + \
            "    push rax\n"
        case IntrinsicKind.OVER:
            return \
            "    pop rax\n" + \
            "    pop rbx\n" + \
            "    push rbx\n" + \
            "    push rax\n" + \
            "    push rbx\n"
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
        case IntrinsicKind.CAST_INT | IntrinsicKind.CAST_STR:
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
    global offset
    data['scopes'].append([])
    buffer = ""
    i = 0
    while i < len(ir):
        op = ir[i]
        if op[0] == IRKind.PushInt:
            buffer += f"    push {op[1]}\n"
        elif op[0] == IRKind.PushStr:
            buffer += f"    push S{op[2]}\n"
            data['strings'].append(op[1:-1])
        elif op[0] == IRKind.PushBool:
            val = 1 if op[1] == 'true' else 0
            buffer += f"    mov BYTE al, {val}\n" + \
                "    push rax\n"
        elif op[0] == IRKind.PushVar:
            off = find_var(data['scopes'], op[1])
            buffer += f"    push QWORD [rbp - {off}]\n"
        elif op[0] == IRKind.Binary:
            buffer += generate_binary_op(op)
        elif op[0] == IRKind.Func:
            offset = 0
            local_var_count = op[2][4]
            buffer += f"{op[1]}:\n" + \
                "    push rbp\n" + \
                "    mov rbp, rsp\n" + \
                "    sub rsp, {}\n".format(local_var_count * 8)
            nargs = len(op[2][1])
            regs = arg_regs[:nargs]
            for reg in regs:
                buffer += f"    push {reg}\n"
            buf, data = generate_body(op[3], data)
            buffer += buf
            data['funcs'][op[1]] = op[2]
            if not op[2][2]:
                buffer += \
                "    add rsp, {}\n".format(local_var_count * 8) + \
                "    pop rbp\n" + \
                "    ret\n"
        elif op[0] == IRKind.Intrinsic:
            buffer += generate_intrinsic(op)
        elif op[0] == IRKind.Call:
            assert data['funcs'][op[1]][0] == IRKind.FuncSign
            signature = data['funcs'][op[1]][1]
            nargs = len(signature)
            regs = arg_regs[:nargs]
            for x in regs:
                buffer += f"    pop {x}\n"
            buffer += f"    call {op[1]}\n"
            if data['funcs'][op[1]][2]:
                buffer += "    push rax\n"
        elif op[0] == IRKind.If:
            buffer += \
            "    pop rax\n" + \
            "    cmp rax, 0\n" + \
            "    je ADDR{}\n".format(op[2])
            buf, data = generate_body(op[1], data)
            buffer += buf
            if op[3]:
                buffer += f"    jmp ADDR{op[4]}\nADDR{op[2]}:\n"
                buf, data = generate_body(op[3], data)
                buffer += buf
                buffer += f"ADDR{op[4]}:\n"
            else:
                buffer += f"ADDR{op[2]}:\n"
        elif op[0] == IRKind.While:
            buffer += \
            f"ADDR{op[1]}:\n"
        elif op[0] == IRKind.Do:
            buffer += \
            "    pop rax\n" + \
            "    cmp rax, 0\n" + \
            "    je ADDR{}\n".format(op[3])
            buf, data = generate_body(op[1], data)
            buffer += buf
            buffer += f"    jmp ADDR{op[2]}\nADDR{op[3]}:\n"
        elif op[0] == IRKind.Destruct:
            for reg in reversed(arg_regs[:int(op[1])]):
                buffer += f"    pop {reg}\n"
        elif op[0] == IRKind.Let:
            reg = arg_regs[:len(op[1])]
            for x, v in enumerate(op[1]):
                offset += 8
                data['scopes'][-1].append({'sym': v, 'offset': offset})
                buffer += f"    pop {reg[x]}\n    mov [rbp - {offset}], {reg[x]}\n"
        elif op[0] == IRKind.Return:
            buffer += \
            "    pop rax\n" + \
            "    add rsp, {}\n".format(op[1] * 8) + \
            "    pop rbp\n" + \
            "    ret\n"
            break
        i += 1
    data['scopes'].pop()
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

    data = {
        'strings': [],
        'funcs': {},
        'scopes': [],
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

    for string, i in data['strings']:
        if isinstance(string, bytes):
            raw_byte: str = ','.join([hex(bytes(x, 'utf-8')[0]) for x in list(string.decode('unicode_escape'))])
            buffer += f"S{i}:\n   db {raw_byte}\n"

    return buffer

def resolve_imports(ir, addr):
    for i, op in enumerate(ir):
        if op[0] == IRKind.Import:
            global root
            global libpath
            module = op[1]
            path = Path(root).parent
            mod_path = os.path.join(path, module) + ".tf"
            # if not found then look for the module in standard library
            if not Path(mod_path).exists():
                mod_path = os.path.join(libpath, module) + ".tf"
                # if the file is still not found then it doesn't exist
                if not Path(mod_path).exists():
                    print(f"tf: module `{module}` doesn't exist")
                    exit(1)
            tokens = list(Lexer(mod_path).lex())
            parser = Parser(mod_path, tokens)
            parser.addr = addr
            mod_ir = list(parser.parse())
            mod_ir = resolve_imports(mod_ir, parser.addr)
            ir.pop(i)
            ir = ir[:i] + mod_ir + ir[i:]
    return ir

def emit_error(msg, node):
    loc = node[-1]
    loc = [loc[0] + 1, loc[1] + 1]
    print(f"{loc}: {msg}")
    exit(1)

def check_var_redefenitions(node, data):
    for d in data['scopes'][-1]:
        if d['sym'] in node[1]:
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
        if node[1] == fn['sym']:
            return fn

    emit_error(f"`{node[1]}` is not defined", node)

def check_binary_op(node, stack, expected, result):
    stack, rhs = pop_without_underflow(stack, node)
    stack, lhs = pop_without_underflow(stack, node)
    if lhs not in expected or rhs not in expected:
        emit_error(f"expected {expected} for {node[1]} but got `{lhs}` and `{rhs}`", node)
    stack.append(result)
    return stack

def type_chk(ir, data, new_scope=False):
    if new_scope:
        data['scopes'].append([])
    stack = data['stack']

    for id, node in enumerate(ir):
        if node[0] == IRKind.PushInt:
            stack.append("int")
        elif node[0] == IRKind.PushStr:
            stack.append("str")
        elif node[0] == IRKind.PushBool:
            stack.append("bool")
        elif node[0] == IRKind.PushVar:
            typ = None
            for i in reversed(range(len(data['scopes']))):
                for d in data['scopes'][i]:
                    if node[1] == d['sym']:
                        typ = d['type']
                        break
            if typ != None:
                stack.append(typ)
            else:
                emit_error(f"`{node[1]}` is not defined", node)
        elif node[0] == IRKind.Binary:
            if node[1] in [BinaryKind.ADD, BinaryKind.SUB, BinaryKind.MUL, BinaryKind.DIV, BinaryKind.SHL, BinaryKind.SHR, BinaryKind.MOD]:
                stack = check_binary_op(node, stack, {"int"}, "int")
            elif node[1] in [BinaryKind.LT, BinaryKind.GT]:
                stack = check_binary_op(node, stack, {"int"}, "bool")
            elif node[1] in [BinaryKind.AND, BinaryKind.OR]:
                stack = check_binary_op(node, stack, {"bool"}, "bool")
            elif node[1] in [BinaryKind.EQ, BinaryKind.NOTEQ]:
                stack = check_binary_op(node, stack, {"int", "bool"}, "bool")
            else:
                emit_error(f"Unexpected binary-op `{node[1]}`", node)
        elif node[0] == IRKind.Func:
            sig = node[2]
            data['func_scope'] = node[1]
            if sig[0] != IRKind.FuncSign:
                emit_error(f"`{node[1]}` does not have a proper signature", node)
            for typ in sig[1]:
                stack.append(typ)
            data['funcs'].append({'sym': node[1], 'sig': sig[1:]})
            if sig[3]:
                if not sig[2]:
                    emit_error(f"`{node[1]}` expects to return `{sig[3]}` but no return statement found", node)
            data = type_chk(node[3], data, True)
            node[2].append(data['locals'])
            data['locals'] = 0
            stack = data['stack']
            unhandled_stack_error(stack, node, f"Unhandled data in `{data['func_scope']}()`, consider dropping {len(stack)} {value_or_values(stack)}")
        elif node[0] == IRKind.Intrinsic:
            if node[1] == IntrinsicKind.PRINT:
                stack, typ = pop_without_underflow(stack, node)
                if typ not in {"int", "bool"}:
                    emit_error(f"`{node[1]}` expects an `int` or `bool` but `{typ}` was given", node)
            elif node[1] == IntrinsicKind.SYSCALL:
                stack, typ = pop_without_underflow(stack, node)
                if typ not in {"int"}:
                    emit_error(f"`{node[1]}` expects an `int` but `{typ}` was given", node)
                stack.append("int")
            elif node[1] == IntrinsicKind.DROP:
                stack, _ = pop_without_underflow(stack, node)
            elif node[1] == IntrinsicKind.SWAP:
                stack, lhs = pop_without_underflow(stack, node)
                stack, rhs = pop_without_underflow(stack, node)
                stack += [lhs, rhs]
            elif node[1] == IntrinsicKind.DUP:
                stack, typ = pop_without_underflow(stack, node)
                stack += [typ, typ]
            elif node[1] == IntrinsicKind.OVER:
                stack, lhs = pop_without_underflow(stack, node)
                stack, rhs = pop_without_underflow(stack, node)
                stack += [rhs, lhs, rhs]
            elif node[1] == IntrinsicKind.ROT:
                stack, one = pop_without_underflow(stack, node)
                stack, two = pop_without_underflow(stack, node)
                stack, three = pop_without_underflow(stack, node)
                stack += [two, one, three]
            elif node[1] == IntrinsicKind.MEM:
                stack.append("int")
            elif node[1] == IntrinsicKind.CAST_INT:
                stack, typ = pop_without_underflow(stack, node)
                stack.append("int")
            elif node[1] == IntrinsicKind.CAST_STR:
                stack, typ = pop_without_underflow(stack, node)
                stack.append("str")
            elif node[1] == IntrinsicKind.READ8:
                stack, addr = pop_without_underflow(stack, node)
                if addr not in {"str", "int"}:
                    emit_error(f"Cannot read `{addr}`", node)
                stack.append("int")
            elif node[1] == IntrinsicKind.WRITE8:
                stack, addr = pop_without_underflow(stack, node)
                if addr not in {"int"}:
                    emit_error(f"Cannot write to `{addr}`", node)
                stack, val = pop_without_underflow(stack, node)
                if val not in {"int"}:
                    emit_error(f"Expected `int` but got `{val}`", node)
            elif node[1] == IntrinsicKind.READ64:
                stack, addr = pop_without_underflow(stack, node)
                if addr not in {"str", "int"}:
                    emit_error(f"Cannot read `{addr}`", node)
                stack.append("int")
            elif node[1] == IntrinsicKind.WRITE64:
                stack, addr = pop_without_underflow(stack, node)
                if addr not in {"int"}:
                    emit_error(f"Cannot write to `{addr}`", node)
                stack, val = pop_without_underflow(stack, node)
                if val not in {"int"}:
                    emit_error(f"Expected `int` but got `{val}`", node)
            elif node[1] == IntrinsicKind.DIVMOD:
                assert False, "TODO: remove this intrinsic and add a separate `mod` binary-op"
            else:
                assert False, f"Undefined intrinsic {node[1]}"
        elif node[0] == IRKind.Call:
            fn = find_func(node, data['funcs'])
            sig = fn['sig']
            for exp_typ in reversed(sig[0]):
                stack, real_typ = pop_without_underflow(stack, node)
                if real_typ != exp_typ:
                    emit_error(f"`{fn['sym']}` Expected {exp_typ} but got {real_typ}", node)
            if sig[1]:
                stack.append(sig[2])
        elif node[0] == IRKind.If:
            stack, cond = pop_without_underflow(stack, node)
            if cond != "bool":
                emit_error(f"`if` expects a `bool` but found `{cond}`", node)
            stack_snap = stack[:]
            data = type_chk(node[1], data, new_scope=True)
            data['stack'] = stack_snap
            if not node[3]:
                unhandled_stack_error(stack, node, f"`if` block modifies the stack, consider dropping {len(stack)} {value_or_values(stack)} or adding an `else` block with same stack order")
            else:
                stack_snap2 = stack[:]
                data = type_chk(node[3], data)
                if stack_snap2 != stack_snap:
                    print("`if`:", stack_snap)
                    print("`else`:", stack_snap2)
                    emit_error(f"`else` has different stack order then `if`", node[3][-1])
        elif node[0] == IRKind.Do:
            stack, cond = pop_without_underflow(stack, node)
            if cond != "bool":
                emit_error(f"`do` expects a `bool` but found `{cond}`", node)
            data = type_chk(node[1], data, new_scope=True)
            stack = data['stack']
        elif node[0] == IRKind.Destruct:
            for val in range(int(node[1])):
                stack, typ = pop_without_underflow(stack, node)
        elif node[0] == IRKind.Let:
            check_var_redefenitions(node, data)
            for i, sym in enumerate(node[1]):
                data['locals'] += 1
                stack, typ = pop_without_underflow(stack, node)
                data['scopes'][-1].append({'sym': sym, 'type': typ})
        elif node[0] == IRKind.Return:
            sig = None
            for fn in data['funcs']:
                if data['func_scope'] == fn['sym']:
                    sig = fn['sig']
            if not sig:
                emit_error(f"function `{data['func_scope']}` is not defined?", node)

            ir[id] = node[:1] + [data['locals']] + node[1:]
            stack, typ = pop_without_underflow(stack, node)
            if sig[1] and not sig[2]:
                emit_error(f"No return type specified for func `{data['func_scope']}` but it returns `{typ}`", node)
            elif sig[1] and sig[2]:
                if typ != sig[2]:
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

def ir_passes(ir, addr):
    data = {}
    data['consts'] = {}
    ir = resolve_imports(ir, addr)
    ir, _ = expand_const(ir, data)
    data = { 'scopes': [], 'funcs': [], 'stack': [], 'func_scope': 'global', 'locals': 0 }
    data = type_chk(ir, data)
    if data['stack']:
        print("Unhandled data on the stack")
    return ir

def expand_const(ir, data):
    for i, op in enumerate(ir):
        if op[0] == IRKind.Const:
            if op[1] in data['consts']:
                print(f"constant `{op[1]}` is already defined")
                exit(1)
            data['consts'][op[1]] = {
                'type': op[2],
                'value': op[3]
            }
        elif op[0] == IRKind.Func:
            if op[1] in data['consts']:
                print(f"`{op[1]}` is already defined as a constant")
                exit(1)
            op[3], data = expand_const(op[3], data)
        elif op[0] == IRKind.Let:
            for sym in op[1]:
                if sym in data['consts']:
                    print(f"`{sym}` is already defined as a constant")
                    exit(1)
        elif op[0] == IRKind.PushVar:
            if op[1] in data['consts']:
                lit = data['consts'][op[1]]
                if lit['type'] == LiteralKind.INT:
                    dtype = IRKind.PushInt
                elif lit['type'] == LiteralKind.STR:
                    dtype = IRKind.PushStr
                ir[i] = (dtype, lit['value'])
        elif op[0] == IRKind.If:
            op[1], data = expand_const(op[1], data)
            if op[3]:
                op[3], data = expand_const(op[3], data)
        elif op[0] == IRKind.Do:
            op[1], data = expand_const(op[1], data)

    return ir, data

def run_command(args):
    buf = '>>> '
    for arg in args:
        buf += arg + " "

    sys.stdout.write(buf + "\n")
    subprocess.call(args)

def compile_program(ir, program_file):
    buffer = generate_x86_64_nasm_linux(ir)
    out_filename = os.path.join(program_file.parent, program_file.stem)

    with open(out_filename + ".asm", "w") as out:
        out.write(buffer)

    run_command(["nasm", "-felf64", out_filename + ".asm"])
    run_command(["ld", "-o", out_filename, out_filename + ".o"])

    return out_filename

def execute(flag, program_file):
    filepath = Path(program_file).absolute()
    if not filepath.exists():
        print(f"tf: `{program_file}` doesn't exist")
        exit(1)
    global root
    root = filepath
    lexer = Lexer(filepath)
    tokens = list(lexer.lex())
    parser = Parser(filepath, tokens)
    ir = list(parser.parse())
    ir = ir_passes(ir, parser.addr)

    if flag == "-r":
        exec_name = compile_program(ir, filepath)
        run_command(["./" + exec_name])
    elif flag == "-c":
        compile_program(ir, filepath)
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
