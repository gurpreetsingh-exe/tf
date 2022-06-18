class Elf64_Ehdr:
    def __init__(self):
        self.e_ident     = b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.e_type      = 2
        self.e_machine   = 62    # Advance Micro Devices x86_64
        self.e_version   = 1
        self.e_entry     = 0     # Unknown
        self.e_phoff     = 0     # Should be 64 bytes into the file
        self.e_shoff     = 0     # Unknown
        self.e_flags     = 0
        self.e_ehsize    = 64    # This header is 64 bytes long
        self.e_phentsize = 56    # Size of a program header is 56, or atleast it should be
        self.e_phnum     = 0     # We don't know yet
        self.e_shentsize = 64    # A section header is 64 bytes long
        self.e_shnum     = 0     # We don't know yet
        self.e_shstrndx  = 0     # ^^^^^^^^^^^^^^^^^

        # Absolute offset from start of file
        self.off_type      = 16
        self.off_machine   = 18
        self.off_version   = 20
        self.off_entry     = 24
        self.off_phoff     = 32
        self.off_shoff     = 40
        self.off_flags     = 48
        self.off_ehsize    = 52
        self.off_phentsize = 54
        self.off_phnum     = 56
        self.off_shentsize = 58
        self.off_shnum     = 60
        self.off_shstrndx  = 62

    def emit(self, gen):
        gen.write(self.e_ident)
        gen.write_u16(self.e_type)
        gen.write_u16(self.e_machine)
        gen.write_u32(self.e_version)
        gen.write_u64(self.e_entry)
        gen.write_u64(self.e_phoff)
        gen.write_u64(self.e_shoff)
        gen.write_u32(self.e_flags)
        gen.write_u16(self.e_ehsize)
        gen.write_u16(self.e_phentsize)
        gen.write_u16(self.e_phnum)
        gen.write_u16(self.e_shentsize)
        gen.write_u16(self.e_shnum)
        gen.write_u16(self.e_shstrndx)

    def set_entry(self, gen, addr):
        self.e_entry = addr
        gen.write_u64_at(addr, self.off_entry)

    def set_phnum(self, gen, num):
        self.e_phnum = num
        gen.write_u16_at(num, self.off_phnum)

    def set_shnum(self, gen, num):
        self.e_shnum = num
        gen.write_u16_at(num, self.off_shnum)

    def set_phoff(self, gen, addr):
        self.e_phoff = addr
        gen.write_u64_at(addr, self.off_phoff)

    def set_shoff(self, gen, addr):
        self.e_shoff = addr
        gen.write_u64_at(addr, self.off_shoff)

    def set_shstrndx(self, gen, num):
        self.e_shstrndx = num
        gen.write_u16_at(num, self.off_shstrndx)

class Elf64_Phdr:
    def __init__(self):
        self.p_type = 0
        self.p_flags = 0
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0
        self.p_memsz = 0
        self.p_align = 0

        self.off_type = 0
        self.off_flags = 4
        self.off_offset = 8
        self.off_vaddr = 16
        self.off_paddr = 24
        self.off_filesz = 32
        self.off_memsz = 40
        self.off_align = 48

    def emit(self, gen):
        gen.write_u32(self.p_type)
        gen.write_u32(self.p_flags)
        gen.write_u64(self.p_offset)
        gen.write_u64(self.p_vaddr)
        gen.write_u64(self.p_paddr)
        gen.write_u64(self.p_filesz)
        gen.write_u64(self.p_memsz)
        gen.write_u64(self.p_align)

    def set_offset(self, gen, addr, at):
        gen.write_u64_at(addr, self.off_offset + at)

    def set_vaddr(self, gen, addr, at):
        gen.write_u64_at(addr + 0x400000, self.off_vaddr + at)

    def set_paddr(self, gen, addr, at):
        gen.write_u64_at(addr + 0x400000, self.off_paddr + at)

    def set_filesz(self, gen, addr, at):
        gen.write_u64_at(addr, self.off_filesz + at)

    def set_memsz(self, gen, addr, at):
        gen.write_u64_at(addr, self.off_memsz + at)

    def set_typ(self, gen, addr, typ):
        self.sh_type = typ
        gen.write_u32_at(typ, self.off_type + addr)


class Elf64_Shdr:
    def __init__(self):
        self.sh_name = 0
        self.sh_type = 0
        self.sh_flags = 0
        self.sh_addr = 0
        self.sh_offset = 0
        self.sh_size = 0
        self.sh_link = 0
        self.sh_info = 0
        self.sh_addralign = 0
        self.sh_entsize = 0

        self.off_name = 0
        self.off_type = 4
        self.off_flags = 8
        self.off_addr = 16
        self.off_offset = 24
        self.off_size = 32
        self.off_link = 40
        self.off_info = 44
        self.off_addralign = 48
        self.off_entsize = 56

    def emit(self, gen):
        gen.write_u32(self.sh_name)
        gen.write_u32(self.sh_type)
        gen.write_u64(self.sh_flags)
        gen.write_u64(self.sh_addr)
        gen.write_u64(self.sh_offset)
        gen.write_u64(self.sh_size)
        gen.write_u32(self.sh_link)
        gen.write_u32(self.sh_info)
        gen.write_u64(self.sh_addralign)
        gen.write_u64(self.sh_entsize)

    def set_name(self, gen, addr, at):
        self.sh_name = addr
        gen.write_u32_at(addr, self.off_name + at)

    def set_typ(self, gen, addr, typ):
        self.sh_type = typ
        gen.write_u32_at(typ, self.off_type + addr)

    def set_offset(self, gen, addr, at):
        gen.write_u64_at(addr, self.off_offset + at)

    def set_size(self, gen, size, at):
        gen.write_u64_at(size, self.off_size + at)

    def set_link(self, gen, addr, link):
        self.sh_link = link
        gen.write_u32_at(link, self.off_link + addr)

class Elf64_Sym:
    def __init__(self):
        self.st_name = 0
        self.st_info = 0
        self.st_other = 0
        self.st_shndx = 0
        self.st_value = 0
        self.st_size = 0
