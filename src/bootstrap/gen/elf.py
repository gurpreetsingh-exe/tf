class Elf64_Ehdr:
    def __init__(self):
        self.e_ident     = b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.e_type      = 2
        self.e_machine   = 62    # Advance Micro Devices x86_64
        self.e_version   = 1
        self.e_entry     = 0     # Unknown
        self.e_phoff     = 64    # Should be 64 bytes into the file
        self.e_shoff     = 0     # Unknown
        self.e_flags     = 0
        self.e_ehsize    = 64    # This header is 64 bytes long
        self.e_phentsize = 56    # Size of a program header is 56, or atleast it should be
        self.e_phnum     = 0     # We don't know yet
        self.e_shentsize = 64    # A section header is 64 bytes long
        self.e_shnum     = 0     # We don't know yet
        self.e_shstrndx  = 0     # ^^^^^^^^^^^^^^^^^

    def emit_ehdr(self, gen):
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
        gen.write_u64_at(addr, 24)

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


class Elf64_Sym:
    def __init__(self):
        self.st_name = 0
        self.st_info = 0
        self.st_other = 0
        self.st_shndx = 0
        self.st_value = 0
        self.st_size = 0
