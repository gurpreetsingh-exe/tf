const SYS_READ 0
const SYS_WRITE 1
const SYS_OPEN 2
const SYS_CLOSE 3
const SYS_STAT 4
const SYS_FSTAT 5
const SYS_MMAP 9
const SYS_MUNMAP 11
const SYS_MREMAP 25
const SYS_EXIT 60

macro read  { ~[3] SYS_READ  syscall }
macro write { ~[3] SYS_WRITE syscall drop }
macro open  { ~[3] SYS_OPEN  syscall }
macro close { ~[1] SYS_CLOSE syscall drop }
macro stat  { ~[2] SYS_STAT  syscall drop }
macro fstat { ~[2] SYS_FSTAT syscall drop }
macro exit  { ~[1] SYS_EXIT  syscall drop }
