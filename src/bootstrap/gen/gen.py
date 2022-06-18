from enum import Enum, auto
import os
from .elf import *


class Reg(Enum):
    rax = auto()
    rbx = auto()
    rcx = auto()
    rdx = auto()
    rsi = auto()
    rdi = auto()
    rbp = auto()
    rsp = auto()


class Gen:
    def __init__(self, out_name):
        self.out_name = out_name
        self.buf = bytearray()
        self.symbols = []
        self.strings = []
        self.labels = []
        self.shdrs = []
        self.phdrs = []
        self.rela = []
        self.ehdr = Elf64_Ehdr()
        self.main = 0

    def gen_exec(self, ir):
        self.ehdr.emit(self)
        self.gen_program_headers()
        # self.gen_hello_world()
        self.gen_text_from_ir(ir)

        __null = self.find_phdr("")
        __null.phdr.set_vaddr(self, 0, __null.addr)
        __null.phdr.set_paddr(self, 0, __null.addr)
        __null.phdr.set_flags(self, 4, __null.addr)

        self.gen_data()
        self.gen_section_headers()

        try:
            with open(self.out_name, "wb") as f:
                f.write(self.buf)
        except FileExistsError:
            with open(self.out_name, "xb") as f:
                f.write(self.buf)
        os.chmod(self.out_name, 0o755)

    def gen_text_from_ir(self, ir):
        text = self.find_phdr(".text")
        text.phdr.set_offset(self, self.curr_addr, text.addr)
        text.phdr.set_vaddr(self, self.curr_addr, text.addr)
        text.phdr.set_paddr(self, self.curr_addr, text.addr)
        text.phdr.set_flags(self, 5, text.addr)
        st = self.curr_addr

        # gen .text stuff
        for _ in ir:
            pass

        self.ehdr.set_entry(self, 0x400000 + self.curr_addr)
        self.mov_reg_to_reg(Reg.rdi, Reg.rsp)
        # self.call("main")
        self.mov_int_to_reg(Reg.rax, 60)
        self.mov_int_to_reg(Reg.rdi, 0)
        self.syscall()

        sz = self.curr_addr - st
        text.phdr.set_filesz(self, sz, text.addr)
        text.phdr.set_memsz(self, sz, text.addr)

    def mov_reg_to_reg(self, r1, r2):
        if r1 == Reg.rdi and r2 == Reg.rsp:
            self.buf += b"\x48\x89\xe7"
        else:
            assert False, f"Unreachable in `mov_reg_to_reg`, \"mov {Reg(r1).name}, {Reg(r2).name}\" is not implemented"

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

    def syscall(self):
        self.buf += b"\x0f\x05"

    def call(self, name):
        self.buf += b"\xe8"
        __rela = lambda x: None
        __rela.name = name
        __rela.addr = self.curr_addr
        self.rela.append(__rela)
        self.write_u64(0)

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

    def gen_program_headers(self):
        self.ehdr.set_phoff(self, self.curr_addr)
        self.create_phdr("", 1)
        self.create_phdr(".text", 1)
        self.create_phdr(".data", 1)

        self.ehdr.set_phnum(self, len(self.phdrs))

    def gen_section_headers(self):
        self.ehdr.set_shoff(self, self.curr_addr)
        self.create_shdr("", 0, 0)
        self.create_shdr(".text", 1, 0)
        self.create_shdr(".data", 1, 0)
        self.create_shdr(".symtab", 2, 24)
        self.create_shdr(".strtab", 3, 0)
        self.create_shdr(".shstrtab", 3, 0)

        symtab = self.find_shdr(".symtab")
        symtab.shdr.set_link(self, symtab.addr, 4)

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

