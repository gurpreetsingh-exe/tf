from enum import Enum, auto
import os
from .elf import *
from Parser import *

class Reg(Enum):
    rax = auto()
    rbx = auto()
    rcx = auto()
    rdx = auto()
    rsi = auto()
    rdi = auto()
    rbp = auto()
    rsp = auto()
    r8  = auto()
    r9  = auto()
    r10 = auto()

arg_regs = [Reg.rdi, Reg.rsi, Reg.rdx, Reg.r10, Reg.r8, Reg.r9]

class Gen:
    def __init__(self, out_name):
        self.out_name = out_name
        self.buf = bytearray()
        self.symbols = []
        self.strings = []
        self.symbol_table = None
        self.shdrs = []
        self.phdrs = []
        self.rela = []
        self.ehdr = Elf64_Ehdr()
        self.main = 0

        self.scopes = []

        self.var_offset = 0
        self.funcs = {}
        self.locs = []

    def gen_exec(self, ir):
        self.ehdr.emit(self)
        self.gen_program_headers()
        # self.gen_hello_world()
        self.gen_text_from_ir(ir)
        self.align()

        __null = self.find_phdr("")
        __null.phdr.set_vaddr(self, 0, __null.addr)
        __null.phdr.set_paddr(self, 0, __null.addr)
        __null.phdr.set_flags(self, 4, __null.addr)

        self.gen_data()
        __bss_start = self.curr_addr
        self.align()
        self.new_sym("__bss_start", 3)
        self.new_sym("mem", 3)
        self.patch_labels()
        self.gen_sym_tab()

        strtab_id = self.curr_addr
        self.write_u8(0)
        self.buf += bytes(f"main.asm", 'utf-8') + b'\x00'
        for sym in self.symbols:
            self.buf += bytes(sym.name, 'utf-8') + b'\x00'
        strtab_sz = self.curr_addr - strtab_id

        self.gen_section_headers()
        self.align()
        symtab = self.find_shdr(".symtab")
        symtab.shdr.set_offset(self, self.symbol_table.addr, symtab.addr)
        symtab.shdr.set_size(self, (len(self.symbols) + 2) * 24, symtab.addr)

        bss = self.find_shdr(".bss")
        bss.shdr.set_addr(self, 0x400000 + symtab.shdr.sh_offset, bss.addr)

        strtab = self.find_shdr(".strtab")
        strtab.shdr.set_offset(self, strtab_id, strtab.addr)
        strtab.shdr.set_size(self, strtab_sz, strtab.addr)

        try:
            with open(self.out_name, "wb") as f:
                f.write(self.buf)
        except FileExistsError:
            with open(self.out_name, "xb") as f:
                f.write(self.buf)
        os.chmod(self.out_name, 0o755)

    def new_sym(self, name, typ):
        for sym in self.symbols:
            if sym.name == name:
                print(f"Symbol re-definition {name}")
                exit(1)
        __sym = lambda x: None
        __sym.name = name
        __sym.typ = typ
        __sym.addr = self.curr_addr
        self.symbols.append(__sym)

    def find_symbol(self, name):
        sym = [s for s in self.symbols if s.name == name]
        if sym:
            return sym[0].addr

    def patch_labels(self):
        for rela in self.rela:
                if (addr:= self.find_symbol(rela.name)) != None:
                    if rela.typ:
                        self.write_u32_at(0xffffffff - (rela.addr + 4 - addr - 1), rela.addr)
                    else:
                        self.write_u32_at(0x400000 + addr, rela.addr)

    def gen_sym_tab(self):
        sym_tab = lambda x: None
        sym_tab.addr = self.curr_addr
        name = 1
        Elf64_Sym(0, 0, 0, 0, 0, 0).emit(self)
        Elf64_Sym(name, 4, 0, 65521, 0, 0).emit(self)
        name += len("main.asm") + 1
        for i, sym in enumerate(self.symbols):
            symb = Elf64_Sym(name, 0, 0, sym.typ, 0x400000 + sym.addr, 0)
            symb.emit(self)
            name += len(sym.name) + 1
        self.symbol_table = sym_tab

    def binary_op(self, op):
        match op[1]:
            case BinaryKind.ADD:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rax)
                    self.pop_reg(Reg.rbx)
                    self.add_reg_to_reg(Reg.rax, Reg.rbx)
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.SUB:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.sub_reg_from_reg(Reg.rax, Reg.rbx)
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.MUL:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rax)
                    self.pop_reg(Reg.rbx)
                    self.mul(Reg.rax, Reg.rbx)
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.DIV:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.cqo()
                    self.div(Reg.rbx)
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.LT:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.sub_reg(Reg.rbx, 1)
                    self.cmp_reg(Reg.rax, Reg.rbx)
                    self.mov_int_to_reg(Reg.rax, 0)
                    # setle al
                    self.buf += b"\x0f\x9e\xc0"
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.GT:
                if op[2] == TypeKind.INT:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.cmp_reg(Reg.rax, Reg.rbx)
                    self.mov_int_to_reg(Reg.rax, 0)
                    # setg al
                    self.buf += b"\x0f\x9f\xc0"
                    self.push_reg(Reg.rax)
                elif op[2] == TypeKind.FLOAT:
                    assert False, "float math is not implemented"
                else:
                    assert False, "Unreachable in binary_op()"
            case BinaryKind.SHL:
                self.pop_reg(Reg.rcx)
                self.pop_reg(Reg.rax)
                self.buf += b"\x48\xd3\xe0"
                self.push_reg(Reg.rax)
            case BinaryKind.SHR:
                self.pop_reg(Reg.rcx)
                self.pop_reg(Reg.rax)
                self.buf += b"\x48\xd3\xf8"
                self.push_reg(Reg.rax)
            case BinaryKind.AND:
                self.pop_reg(Reg.rax)
                self.pop_reg(Reg.rbx)
                self.test(Reg.rax)
                # setne al
                self.buf += b"\x0f\x95\xc0"
                self.test(Reg.rbx)
                # setne bl
                self.buf += b"\x0f\x95\xc3"
                # and rax, rbx
                self.buf += b"\x48\x21\xd8"
                self.push_reg(Reg.rax)
            case BinaryKind.OR:
                self.pop_reg(Reg.rax)
                self.pop_reg(Reg.rbx)
                self.test(Reg.rax)
                # setne al
                self.buf += b"\x0f\x95\xc0"
                self.test(Reg.rbx)
                # setne bl
                self.buf += b"\x0f\x95\xc3"
                # or rax, rbx
                self.buf += b"\x48\x09\xd8"
                self.push_reg(Reg.rax)
            case BinaryKind.MOD:
                self.pop_reg(Reg.rbx)
                self.pop_reg(Reg.rax)
                self.xor(Reg.rdx)
                self.div(Reg.rbx)
                self.push_reg(Reg.rdx)
            case BinaryKind.EQ:
                self.pop_reg(Reg.rax)
                self.pop_reg(Reg.rbx)
                self.cmp_reg(Reg.rax, Reg.rbx)
                self.mov_int_to_reg(Reg.rax, 0)
                # sete al
                self.buf += b"\x0f\x94\xc0"
                self.push_reg(Reg.rax)
            case BinaryKind.NOTEQ:
                self.pop_reg(Reg.rax)
                self.pop_reg(Reg.rbx)
                self.cmp_reg(Reg.rax, Reg.rbx)
                self.mov_int_to_reg(Reg.rax, 0)
                # setne al
                self.buf += b"\x0f\x95\xc0"
                self.push_reg(Reg.rax)
            case _:
                assert False, f"{op[1]} not implemented in binary_op()"

    def find_var(self, op):
        size = len(self.scopes)
        for i in reversed(range(size)):
            for d in self.scopes[i]:
                if op[1] == d['sym']:
                    return d['offset']

    def find_str(self, str_to_find):
        for s, str_addr in self.strings:
            if str_to_find == s:
                return str_addr

    def gen_body(self, ir):
        i = 0
        self.scopes.append([])
        while i < len(ir):
            op = ir[i]
            if op[0] == IRKind.PushInt:
                self.push_int(int(op[1]))
            elif op[0] == IRKind.PushStr:
                self.buf += b"\x68"
                if addr := self.find_str(op[1]):
                    self.label(f"S{addr}", 0)
                else:
                    self.label(f"S{op[2]}", 0)
                    self.strings.append(op[1:-1])
            elif op[0] == IRKind.PushVar:
                offset = self.find_var(op)
                byt = offset <= (0xff // 2) + 1
                if byt:
                    self.buf += b"\xff\x75"
                    self.write_u8(0xff - offset + 1)
                else:
                    self.buf += b"\xff\xb5"
                    self.write_u32(0xffffffff - offset + 1)
            elif op[0] == IRKind.PushAddr:
                offset = self.find_var(op)
                self.lea_var(offset)
                self.push_reg(Reg.rax)
            elif op[0] == IRKind.Binary:
                self.binary_op(op)
            elif op[0] == IRKind.Func:
                self.var_offset = 0
                self.new_sym(op[1], 1)
                self.push_reg(Reg.rbp)
                self.mov_reg_to_reg(Reg.rbp, Reg.rsp)
                local_var_count = op[2][4]
                self.sub_reg(Reg.rsp, local_var_count * 8)
                nargs = len(op[2][1])
                regs = arg_regs[:nargs]
                for reg in regs:
                    self.push_reg(reg)
                self.gen_body(op[3])
                self.funcs[op[1]] = op[2]
                if not op[2][2]:
                    self.add_reg(Reg.rsp, local_var_count * 8)
                    self.pop_reg(Reg.rbp)
                    self.ret()
            elif op[0] == IRKind.Intrinsic:
                if op[1] == IntrinsicKind.PRINT:
                    self.pop_reg(Reg.rdi)
                    self.call("print")
                elif op[1] == IntrinsicKind.DROP:
                    self.buf += b"\x48\x8d\x64\x24\x08"
                elif op[1] == IntrinsicKind.SWAP:
                    self.pop_reg(Reg.rax)
                    # TODO: make this a `dup` method
                    self.buf += b"\xff\x34\x24"
                    # mov [rsp + 8], rax
                    self.buf += b"\x48\x89\x44\x24\x08"
                elif op[1] == IntrinsicKind.DUP:
                    self.buf += b"\xff\x34\x24"
                elif op[1] == IntrinsicKind.OVER:
                    self.buf += b"\xff\x74\x24\x08"
                elif op[1] == IntrinsicKind.ROT:
                    self.pop_reg(Reg.rax)
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rcx)
                    self.push_reg(Reg.rbx)
                    self.push_reg(Reg.rax)
                    self.push_reg(Reg.rcx)
                elif op[1] == IntrinsicKind.MEM:
                    self.buf += b"\x68"
                    self.label("mem", 0)
                elif op[1] == IntrinsicKind.READ8:
                    self.pop_reg(Reg.rax)
                    self.mov_int_to_reg(Reg.rbx, 0)
                    self.buf += b"\x8a\x18"
                    self.push_reg(Reg.rax)
                elif op[1] == IntrinsicKind.WRITE8:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.buf += b"\x88\x18"
                elif op[1] == IntrinsicKind.READ64:
                    self.pop_reg(Reg.rax)
                    self.mov_int_to_reg(Reg.rbx, 0)
                    self.buf += b"\x48\x8b\x18"
                    self.push_reg(Reg.rbx)
                elif op[1] == IntrinsicKind.WRITE64:
                    self.pop_reg(Reg.rbx)
                    self.pop_reg(Reg.rax)
                    self.buf += b"\x48\x89\x18"
                elif op[1] == IntrinsicKind.SYSCALL:
                    self.pop_reg(Reg.rax)
                    self.syscall()
                    self.push_reg(Reg.rax)
                elif op[1] == IntrinsicKind.HERE:
                    self.buf += b"\x68"
                    self.label(f"__here{len(self.locs)}", 0)
                    self.locs.append(op[-1])
                else:
                    assert False, f"{op[1]} is not implemented"
            elif op[0] == IRKind.Call:
                assert self.funcs[op[1]][0] == IRKind.FuncSign
                signature = self.funcs[op[1]][1]
                nargs = len(signature)
                regs = arg_regs[:nargs]
                for x in regs:
                    self.pop_reg(x)
                self.call(op[1])
                if self.funcs[op[1]][2]:
                    self.push_reg(Reg.rax)
            elif op[0] == IRKind.If:
                self.pop_reg(Reg.rax)
                self.cmp(Reg.rax, 0)
                self.je(f"ADDR{op[2]}")
                self.gen_body(op[1])
                if op[3]:
                    self.jmp(f"ADDR{op[4]}")
                    self.new_sym(f"ADDR{op[2]}", 1)
                    self.gen_body(op[3])
                    self.new_sym(f"ADDR{op[4]}", 1)
                else:
                    self.new_sym(f"ADDR{op[2]}", 1)
            elif op[0] == IRKind.While:
                self.new_sym(f"ADDR{op[1]}", 1)
            elif op[0] == IRKind.Do:
                self.pop_reg(Reg.rax)
                self.cmp(Reg.rax, 0)
                self.je(f"ADDR{op[3]}")
                self.gen_body(op[1])
                self.jmp(f"ADDR{op[2]}")
                self.new_sym(f"ADDR{op[3]}", 1)
            elif op[0] == IRKind.Let:
                reg = arg_regs[:len(op[1])]
                for x, v in enumerate(op[1]):
                    self.var_offset += 8
                    self.scopes[-1].append({'sym': v, 'offset': self.var_offset})
                    self.def_var(self.var_offset, reg[x])
            elif op[0] == IRKind.Destruct:
                for reg in reversed(arg_regs[:int(op[1])]):
                    self.pop_reg(reg)
            elif op[0] == IRKind.Return:
                self.pop_reg(Reg.rax)
                self.add_reg(Reg.rsp, int(op[1]) * 8)
                self.pop_reg(Reg.rbp)
                self.ret()
            elif op[0] in [IRKind.Const, IRKind.Import, IRKind.Macro]:
                # TODO: resolve these in previous passes
                pass
            else:
                assert False, f"{op} is not implemented"
            i += 1
        self.scopes.pop()

    def gen_text_from_ir(self, ir):
        text = self.find_phdr(".text")
        text.phdr.set_offset(self, self.curr_addr, text.addr)
        text.phdr.set_vaddr(self, self.curr_addr, text.addr)
        text.phdr.set_paddr(self, self.curr_addr, text.addr)
        text.phdr.set_flags(self, 5, text.addr)
        st = self.curr_addr

        # I'm not cheating you're cheating
        self.new_sym("print", 1)
        self.buf += b"\x49\xb8\xcd\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x48\x83\xec\x28\xc6\x44"
        self.buf += b"\x24\x1f\x0a\x4c\x8d\x4c\x24\x1e\x4c\x89\xc9\x48\x89\xf8\x49\xf7"
        self.buf += b"\xe0\x48\x89\xf8\x48\xc1\xea\x03\x48\x8d\x34\x92\x48\x01\xf6\x48"
        self.buf += b"\x29\xf0\x48\x89\xce\x48\x83\xe9\x01\x83\xc0\x30\x88\x41\x01\x48"
        self.buf += b"\x89\xf8\x48\x89\xd7\x48\x83\xf8\x09\x77\xd0\x41\x8d\x51\x02\xb8"
        self.buf += b"\x20\x00\x00\x00\xbf\x01\x00\x00\x00\x29\xf2\x48\x63\xd2\x48\x29"
        self.buf += b"\xd0\x48\x8d\x34\x04\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x28\xc3"

        # gen .text stuff
        self.gen_body(ir)

        self.new_sym("_start", 1)
        self.ehdr.set_entry(self, 0x400000 + self.curr_addr)
        self.mov_reg_to_reg(Reg.rdi, Reg.rsp)
        self.call("main")
        self.mov_int_to_reg(Reg.rax, 60)
        self.mov_int_to_reg(Reg.rdi, 0)
        self.syscall()

        sz = self.curr_addr - st
        text.phdr.set_filesz(self, sz, text.addr)
        text.phdr.set_memsz(self, sz, text.addr)

    def cmp(self, reg, val):
        byt = val <= 0xff // 2
        match reg:
            case Reg.rax:
                self.buf += b"\x48\x83\xf8" if byt else b"\x48\x3d"
            case _:
                assert False, f"Not implemented in cmp(), \"cmp {Reg(reg).name}, {val}\""

        if byt:
            self.write_u8(val)
        else:
            self.write_u32(val)

    def cmp_reg(self, r1, r2):
        if r1 == Reg.rax and r2 == Reg.rbx:
            self.buf += b"\x48\x39\xd8"
        else:
            assert False, f"not implemented in cmp_reg(), \"cmp {Reg(r1).name}, {Reg(r2).name}\""

    def test(self, reg):
        self.buf += b"\x48\x85"
        match reg:
            case Reg.rax:
                self.buf += b"\xc0"
            case Reg.rbx:
                self.buf += b"\xdb"
            case _:
                assert False, "not implemented in test()"

    def je(self, label):
        self.buf += b"\x0f\x84"
        self.label(label, 1)

    def jmp(self, label):
        self.buf += b"\xe9"
        self.label(label, 1)

    def lea_var(self, offset):
        if offset <= (0xff // 2) + 1:
            self.buf += b"\x48\x8d\x45"
            self.write_u8(0xff - offset + 1)
        else:
            self.buf += b"\x48\x8d\x85"
            self.write_u32(0xffffffff - offset + 1)

    def def_var(self, offset, reg):
        self.pop_reg(reg)
        if reg in arg_regs[:3]:
            self.buf += b"\x48\x89"
        elif reg in arg_regs[3:]:
            self.buf += b"\x4c\x89"
        byt = offset <= (0xff // 2) + 1
        match reg:
            case Reg.rdi:
                reg_byte = 0x7d
            case Reg.rsi:
                reg_byte = 0x75
            case Reg.rdx | Reg.r10:
                reg_byte = 0x55
            case Reg.r8:
                reg_byte = 0x45
            case Reg.r9:
                reg_byte = 0x4d
        if byt:
            self.write_u8(reg_byte)
            self.write_u8(0xff - offset + 1)
        else:
            self.write_u8(reg_byte + 64)
            self.write_u32(0xffffffff - offset + 1)

    def mov_reg_to_reg(self, r1, r2):
        if r1 == Reg.rdi and r2 == Reg.rsp:
            self.buf += b"\x48\x89\xe7"
        elif r1 == Reg.rbp and r2 == Reg.rsp:
            self.buf += b"\x48\x89\xe5"
        else:
            assert False, f"Unreachable in `mov_reg_to_reg`, \"mov {Reg(r1).name}, {Reg(r2).name}\" is not implemented"

    def add_reg_to_reg(self, r1, r2):
        if r1 == Reg.rax and r2 == Reg.rbx:
            self.buf += b"\x48\x01\xd8"

    def sub_reg_from_reg(self, r1, r2):
        if r1 == Reg.rax and r2 == Reg.rbx:
            self.buf += b"\x48\x29\xd8"

    def xor(self, reg):
        self.buf += b"\x48\x31"
        match reg:
            case Reg.rax:
                self.buf += b"\xc0"
            case Reg.rbx:
                self.buf += b"\xdb"
            case Reg.rcx:
                self.buf += b"\xc9"
            case Reg.rdx:
                self.buf += b"\xd2"
            case _:
                assert False, "not implemented"

    def mul(self, r1, r2):
        if r1 == Reg.rax and r2 == Reg.rbx:
            self.buf += b"\x48\x0f\xaf\xc3"
        else:
            assert False, "not implemented in mul()"

    def cqo(self):
        self.buf += b"\x48\x99"

    def div(self, reg):
        self.buf += b"\x48\xf7"
        match reg:
            case Reg.rax:
                self.buf += b"\xf8"
            case Reg.rbx:
                self.buf += b"\xfb"
            case _:
                assert False, f"Not implemented in div(), `div {Reg(reg).name}`"

    def pop_reg(self, reg):
        match reg:
            case Reg.rax:
                self.buf += b"\x58"
            case Reg.rbx:
                self.buf += b"\x5b"
            case Reg.rcx:
                self.buf += b"\x59"
            case Reg.rbp:
                self.buf += b"\x5d"
            case Reg.rdi:
                self.buf += b"\x5f"
            case Reg.rsi:
                self.buf += b"\x5e"
            case Reg.rdx:
                self.buf += b"\x5a"
            case Reg.r10:
                self.buf += b"\x41\x5a"
            case Reg.r8:
                self.buf += b"\x41\x58"
            case Reg.r9:
                self.buf += b"\x41\x59"
            case _:
                assert False, f"not implemented in pop_reg(), \"pop {Reg(reg).name}\""

    def ret(self):
        self.buf += b"\xc3"

    def mov_int_to_reg(self, reg, val):
        if val >= 2**32:
            self.buf += b"\x48"
        match reg:
            case Reg.rax:
                self.buf += b"\xb8"
            case Reg.rbx:
                self.buf += b"\xbb"
            case Reg.rcx:
                self.buf += b"\xb9"
            case Reg.rdx:
                self.buf += b"\xba"
            case Reg.rsi:
                self.buf += b"\xbe"
            case Reg.rdi:
                self.buf += b"\xbf"
            case Reg.rbp:
                self.buf += b"\xbd"
            case Reg.rsp:
                self.buf += b"\xbc"
        if val >= 2**32:
            self.write_u64(val)
        else:
            self.write_u32(val)

    def push_int(self, val):
        byt = val <= 0xff // 2
        if byt:
            self.buf += b"\x6a"
            self.write_u8(val)
        else:
            self.buf += b"\x68"
            self.write_u32(val)

    def push_reg(self, reg):
        match reg:
            case Reg.rax:
                self.buf += b"\x50"
            case Reg.rbx:
                self.buf += b"\x53"
            case Reg.rcx:
                self.buf += b"\x51"
            case Reg.rdx:
                self.buf += b"\x52"
            case Reg.rsi:
                self.buf += b"\x56"
            case Reg.rdi:
                self.buf += b"\x57"
            case Reg.rbp:
                self.buf += b"\x55"
            case Reg.rsp:
                self.buf += b"\x54"
            case Reg.r8:
                self.buf += b"\x41\x50"
            case Reg.r9:
                self.buf += b"\x41\x51"
            case Reg.r10:
                self.buf += b"\x41\x52"

    def sub_reg(self, reg, val):
        byt = val <= 0xff // 2
        val = val & (2**32) // 2 - 1
        mid = b"\x83" if byt else b"\x81"
        match reg:
            case Reg.rsp:
                self.buf += b"\x48" + mid + b"\xec"
            case Reg.rbx:
                self.buf += b"\x48" + mid + b"\xeb"
        if byt:
            self.buf.append(val)
        else:
            self.write_u32(val)

    def add_reg(self, reg, val):
        byt = val <= 0xff // 2
        val = val & (2**32) // 2 - 1
        match reg:
            case Reg.rsp:
                mid = b"\x83" if byt else b"\x81"
                self.buf += b"\x48" + mid + b"\xc4"
        if byt:
            self.buf.append(val)
        else:
            self.write_u32(val)

    def syscall(self):
        self.buf += b"\x0f\x05"

    def call(self, name):
        self.buf += b"\xe8"
        __rela = lambda x: None
        __rela.name = name
        __rela.addr = self.curr_addr
        __rela.typ = 1
        self.rela.append(__rela)
        self.write_u32(0)

    def label(self, name, typ):
        __rela = lambda x: None
        __rela.name = name
        __rela.addr = self.curr_addr
        __rela.typ = typ
        self.rela.append(__rela)
        self.write_u32(0)

    def gen_hello_world(self):
        text = self.find_phdr(".text")
        text.phdr.set_offset(self, self.curr_addr, text.addr)
        text.phdr.set_vaddr(self, self.curr_addr, text.addr)
        text.phdr.set_paddr(self, self.curr_addr, text.addr)
        text.phdr.set_flags(self, 5, text.addr)
        self.ehdr.set_entry(self, 0x400000 + self.curr_addr)

        st = self.curr_addr
        self.buf += b"\xbf\x01\x00\x00\x00"              #  mov edi, 1
        self.buf += b"\x48\xbe"
        self.symbols.append(["hw", self.curr_addr])
        self.buf += b"00000000"
        self.buf += b"\xba\x0c\x00\x00\x00"              #  mov edx, 12
        self.buf += b"\xb8\x01\x00\x00\x00"              #  mov eax, 1
        self.buf += b"\x0f\x05"                          #  syscall

        self.buf += b"\xbf\x00\x00\x00\x00"              #  mov edi, 0
        self.buf += b"\xb8\x3c\x00\x00\x00"              #  mov eax, 60
        self.buf += b"\x0f\x05"                          #  syscall

        sz = self.curr_addr - st
        text.phdr.set_filesz(self, sz, text.addr)
        text.phdr.set_memsz(self, sz, text.addr)

    def gen_data(self):
        data = self.find_phdr(".data")
        data.phdr.set_offset(self, self.curr_addr, data.addr)
        data.phdr.set_vaddr(self, self.curr_addr, data.addr)
        data.phdr.set_paddr(self, self.curr_addr, data.addr)

        st = self.curr_addr
        for s in self.strings:
            self.new_sym(f"S{s[1]}", 2)
            self.write(bytes(s[0].decode('unicode_escape'), 'utf-8') + b"\x00")
        for x, loc in enumerate(self.locs):
            self.new_sym(f"__here{x}", 2)
            self.write_u64(loc[0])
            self.write_u64(loc[1])
        sz = self.curr_addr - st
        data.phdr.set_filesz(self, sz, data.addr)
        data.phdr.set_memsz(self, sz, data.addr)
        # TODO: find out why this would segfault when set to 6 (RW)
        data.phdr.set_flags(self, 7, data.addr)

    def align(self):
        self.buf += bytes(16 - self.curr_addr % 16)

    def gen_program_headers(self):
        self.ehdr.set_phoff(self, self.curr_addr)
        self.create_phdr("", 1)
        self.create_phdr(".text", 1)
        self.create_phdr(".data", 1)
        __null = self.find_phdr("")
        __null.phdr.set_filesz(self, self.curr_addr, __null.addr)
        __null.phdr.set_memsz(self, self.curr_addr, __null.addr)

        self.align()

        self.ehdr.set_phnum(self, len(self.phdrs))

    def gen_section_headers(self):
        self.ehdr.set_shoff(self, self.curr_addr)
        self.create_shdr("", 0, 0)
        self.create_shdr(".text", 1, 0)
        self.create_shdr(".data", 1, 0)
        self.create_shdr(".bss", 8, 0)
        self.create_shdr(".symtab", 2, 24)
        self.create_shdr(".strtab", 3, 0)
        self.create_shdr(".shstrtab", 3, 0)

        text_shdr = self.find_shdr(".text")
        text_phdr = self.find_phdr(".text")
        text_shdr.shdr.set_size(self, text_phdr.phdr.p_filesz, text_shdr.addr)
        text_shdr.shdr.set_offset(self, text_phdr.phdr.p_offset, text_shdr.addr)
        text_shdr.shdr.set_addr(self, text_phdr.phdr.p_vaddr, text_shdr.addr)
        text_shdr.shdr.set_flags(self, 6, text_shdr.addr)

        data_shdr = self.find_shdr(".data")
        data_phdr = self.find_phdr(".data")
        data_shdr.shdr.set_size(self, data_phdr.phdr.p_filesz, data_shdr.addr)
        data_shdr.shdr.set_offset(self, data_phdr.phdr.p_offset, data_shdr.addr)
        data_shdr.shdr.set_addr(self, data_phdr.phdr.p_vaddr, data_shdr.addr)
        data_shdr.shdr.set_flags(self, 3, data_shdr.addr)

        symtab = self.find_shdr(".symtab")
        symtab.shdr.set_link(self, len(self.shdrs) - 2, symtab.addr)
        symtab.shdr.set_info(self, symtab.addr, len(self.symbols) + 2)

        bss = self.find_shdr(".bss")
        bss.shdr.set_offset(self, data_phdr.phdr.p_offset + data_phdr.phdr.p_filesz, bss.addr)
        bss.shdr.set_size(self, 1024, bss.addr)
        bss.shdr.set_flags(self, 3, bss.addr)

        self.ehdr.set_shnum(self, len(self.shdrs))

        shstrtab = self.find_shdr(".shstrtab")
        shstrtab.shdr.set_offset(self, self.curr_addr, shstrtab.addr)
        self.emit_shstrtab(shstrtab)
        self.ehdr.set_shstrndx(self, len(self.shdrs) - 1)

    @property
    def curr_addr(self):
        return len(self.buf)

    def find_shdr(self, name):
        for shdr in self.shdrs:
            if shdr.name == name:
                return shdr

    def find_phdr(self, name):
        for phdr in self.phdrs:
            if phdr.name == name:
                return phdr

    def emit_shstrtab(self, shstrtab):
        buf = bytes()
        for shdr in self.shdrs:
            shdr.shdr.set_name(self, len(buf), shdr.addr)
            buf += bytes(shdr.name, 'utf-8') + b'\x00'
        self.buf += buf
        shstrtab.shdr.set_size(self, len(buf), shstrtab.addr)

    def create_phdr(self, name, typ):
        phdr = Elf64_Phdr()
        phdr.p_type = typ
        __phdr = lambda x: None
        __phdr.name = name
        __phdr.phdr = phdr
        __phdr.addr = self.curr_addr
        self.phdrs.append(__phdr)
        phdr.emit(self)

    def create_shdr(self, name, typ, entsz):
        shdr = Elf64_Shdr()
        shdr.sh_type = typ
        shdr.sh_entsize = entsz
        __shdr = lambda x: None
        __shdr.name = name
        __shdr.shdr = shdr
        __shdr.addr = self.curr_addr
        self.shdrs.append(__shdr)
        shdr.emit(self)

    def write_u8(self, n: int) -> None:
        self.buf.append(n & 0xff)

    def write_u16(self, n: int) -> None:
        buf = bytearray()
        buf.append(n & 0xff)
        buf.append((n >> 8) & 0xff)
        self.buf += buf

    def write_u32(self, n: int) -> None:
        buf = bytearray()
        buf.append(n & 0xff)
        buf.append((n >> 8) & 0xff)
        buf.append((n >> 16) & 0xff)
        buf.append((n >> 24) & 0xff)
        self.buf += buf

    def write_u64(self, n: int) -> None:
        buf = bytearray()
        buf.append(n & 0xff)
        buf.append((n >> 8) & 0xff)
        buf.append((n >> 16) & 0xff)
        buf.append((n >> 24) & 0xff)
        buf.append((n >> 32) & 0xff)
        buf.append((n >> 40) & 0xff)
        buf.append((n >> 48) & 0xff)
        buf.append((n >> 56) & 0xff)
        self.buf += buf

    def write(self, buf: bytes) -> None:
        self.buf += buf

    def write_u8_at(self, n: int, addr: int) -> None:
        if self.curr_addr < addr:
            print(f"Cannot write to buf in write_u8_at, buf_size: {self.curr_addr}, addr: {addr}")
            exit(1)

        self.buf[addr] = n & 0xff

    def write_u16_at(self, n: int, addr: int) -> None:
        if self.curr_addr < addr:
            print(f"Cannot write to buf in write_u16_at, buf_size: {self.curr_addr}, addr: {addr}")
            exit(1)

        self.buf[addr] = n & 0xff
        self.buf[addr + 1] = (n >> 8) & 0xff

    def write_u32_at(self, n: int, addr: int) -> None:
        if self.curr_addr < addr:
            print(f"Cannot write to buf in write_u32_at, buf_size: {self.curr_addr}, addr: {addr}")
            exit(1)

        self.buf[addr] = n & 0xff
        self.buf[addr + 1] = (n >> 8) & 0xff
        self.buf[addr + 2] = (n >> 16) & 0xff
        self.buf[addr + 3] = (n >> 24) & 0xff

    def write_u64_at(self, n: int, addr: int) -> None:
        if self.curr_addr < addr:
            print(f"Cannot write to buf in write_u64_at, buf_size: {self.curr_addr}, addr: {addr}")
            exit(1)

        self.buf[addr] = n & 0xff
        self.buf[addr + 1] = (n >> 8) & 0xff
        self.buf[addr + 2] = (n >> 16) & 0xff
        self.buf[addr + 3] = (n >> 24) & 0xff
        self.buf[addr + 4] = (n >> 32) & 0xff
        self.buf[addr + 5] = (n >> 40) & 0xff
        self.buf[addr + 6] = (n >> 48) & 0xff
        self.buf[addr + 7] = (n >> 56) & 0xff

