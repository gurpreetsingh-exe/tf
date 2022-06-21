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

        self.var_offset = 0
        self.data = {}

    def gen_exec(self, ir):
        self.ehdr.emit(self)
        self.gen_program_headers()
        # self.gen_hello_world()
        self.gen_text_from_ir(ir)
        self.align()

        self.patch_labels()

        __null = self.find_phdr("")
        __null.phdr.set_vaddr(self, 0, __null.addr)
        __null.phdr.set_paddr(self, 0, __null.addr)
        __null.phdr.set_flags(self, 4, __null.addr)

        self.gen_data()
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

    def new_sym(self, name):
        for sym in self.symbols:
            if sym.name == name:
                print(f"Symbol re-definition {name}")
                exit(1)
        __sym = lambda x: None
        __sym.name = name
        __sym.addr = self.curr_addr
        self.symbols.append(__sym)

    def find_symbol(self, name):
        sym = [s for s in self.symbols if s.name == name]
        if sym:
            return sym[0].addr

    def patch_labels(self):
        for rela in self.rela:
            if (addr:= self.find_symbol(rela.name)) != None:
                self.write_u32_at(0xffffffff - (rela.addr + 4 - addr - 1), rela.addr)

    def gen_sym_tab(self):
        sym_tab = lambda x: None
        sym_tab.addr = self.curr_addr
        name = 1
        Elf64_Sym(0, 0, 0, 0, 0, 0).emit(self)
        Elf64_Sym(name, 4, 0, 65521, 0, 0).emit(self)
        name += len("main.asm") + 1
        for i, sym in enumerate(self.symbols):
            symb = Elf64_Sym(name, 0, 0, 1, 0x400000 + sym.addr, 0)
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

    def gen_body(self, ir):
        i = 0
        while i < len(ir):
            op = ir[i]
            if op[0] == IRKind.PushInt:
                self.push_int(int(op[1]))
            elif op[0] == IRKind.Binary:
                self.binary_op(op)
            elif op[0] == IRKind.Func:
                self.var_offset = 0
                self.new_sym(op[1])
                self.push_reg(Reg.rbp)
                self.mov_reg_to_reg(Reg.rbp, Reg.rsp)
                local_var_count = op[2][4]
                self.sub_reg(Reg.rsp, local_var_count * 8)
                nargs = len(op[2][1])
                regs = arg_regs[:nargs]
                for reg in regs:
                    self.push_reg(reg)
                self.gen_body(op[3])
                self.add_reg(Reg.rsp, local_var_count * 8)
                self.pop_reg(Reg.rbp)
                self.ret()
            else:
                print(op)
            i += 1

    def gen_text_from_ir(self, ir):
        text = self.find_phdr(".text")
        text.phdr.set_offset(self, self.curr_addr, text.addr)
        text.phdr.set_vaddr(self, self.curr_addr, text.addr)
        text.phdr.set_paddr(self, self.curr_addr, text.addr)
        text.phdr.set_flags(self, 5, text.addr)
        st = self.curr_addr

        # gen .text stuff
        self.gen_body(ir)

        self.ehdr.set_entry(self, 0x400000 + self.curr_addr)
        self.new_sym("_start")
        self.mov_reg_to_reg(Reg.rdi, Reg.rsp)
        self.call("main")
        self.mov_int_to_reg(Reg.rax, 60)
        self.mov_int_to_reg(Reg.rdi, 0)
        self.syscall()

        sz = self.curr_addr - st
        text.phdr.set_filesz(self, sz, text.addr)
        text.phdr.set_memsz(self, sz, text.addr)

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

    def pop_reg(self, reg):
        match reg:
            case Reg.rax:
                self.buf += b"\x58"
            case Reg.rbx:
                self.buf += b"\x5b"
            case Reg.rbp:
                self.buf += b"\x5d"

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
        match reg:
            case Reg.rsp:
                mid = b"\x83" if byt else b"\x81"
                self.buf += b"\x48" + mid + b"\xec"
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
        pass
        # self.write_u64_at(self.curr_addr + 0x400000, self.symbols[0][1])
        # self.write(b"Hello World\n")

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
        self.create_shdr(".symtab", 2, 24)
        self.create_shdr(".strtab", 3, 0)
        self.create_shdr(".shstrtab", 3, 0)

        text_shdr = self.find_shdr(".text")
        text_phdr = self.find_phdr(".text")
        # self.write_u64_at(text_phdr.phdr.p_filesz, text_shdr.addr)
        text_shdr.shdr.set_size(self, text_phdr.phdr.p_filesz, text_shdr.addr)
        text_shdr.shdr.set_offset(self, text_phdr.phdr.p_offset, text_shdr.addr)
        text_shdr.shdr.set_addr(self, text_phdr.phdr.p_vaddr, text_shdr.addr)

        symtab = self.find_shdr(".symtab")
        symtab.shdr.set_link(self, symtab.addr, 4)
        # symtab.shdr.set_info(self, symtab.addr, 10)

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

