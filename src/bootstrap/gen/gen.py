from .elf import *

class Gen:
    def __init__(self, out_name):
        self.out_name = out_name
        self.buf = bytearray()
        self.symbols = []
        self.strings = []
        self.labels = []
        self.shdrs = []
        self.ehdr = Elf64_Ehdr()

    def gen_exec(self):
        self.ehdr.emit(self)
        self.ehdr.set_entry(self, 0x401100)
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

        try:
            with open(self.out_name, "wb") as f:
                f.write(self.buf)
        except FileExistsError:
            with open(self.out_name, "xb") as f:
                f.write(self.buf)

    @property
    def curr_addr(self):
        return len(self.buf)

    def find_shdr(self, name):
        for shdr in self.shdrs:
            if shdr.name == name:
                return shdr

    def emit_shstrtab(self, shstrtab):
        buf = bytes()
        for shdr in self.shdrs:
            shdr.shdr.set_name(self, len(buf), shdr.addr)
            buf += bytes(shdr.name, 'utf-8') + b'\x00'
        self.buf += buf
        shstrtab.shdr.set_size(self, len(buf), shstrtab.addr)

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

