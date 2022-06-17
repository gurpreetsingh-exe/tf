class Elf64_Ehdr:
    def __init__(self):
        self.e_ident = 0
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0


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
