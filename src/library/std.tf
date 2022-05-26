const STDIN 0
const STDOUT 1
const STDERR 2

const SYS_READ 0
const SYS_WRITE 1
const SYS_OPEN 2
const SYS_CLOSE 3
const SYS_STAT 4
const SYS_FSTAT 5
const SYS_MMAP 9
const SYS_MUNMAP 11
const SYS_EXIT 60


const PROT_NONE 0
const PROT_READ 1
const PROT_WRITE 2
const PROT_EXEC 4
const PROT_SEM 8


const MAP_SHARED 1
const MAP_PRIVATE 2
const MAP_TYPE 15
const MAP_FIXED 16
const MAP_ANONYMOUS 32

const MAP_ANON 32
const MAP_FILE 0

const O_RDONLY 0

const STATBUF_SIZE 144

func:int string_len(str) {
    let string;
    0 while dup string cast_int + read8 0 > do { 1+ }
    return
}

func println(str) {
    dup string_len()
    let length, string;
    string cast_int length + 10 write8 // add newline
    SYS_WRITE STDOUT string length 1 + ~[3] syscall ~[1]
}

func:int read(int, int, int) {
    let fd, buf, size;
    fd buf size ~[3] SYS_READ syscall
    return
}

func write(int, str, int) {
    ~[3] SYS_WRITE syscall drop
}

// TODO: there is a stack alignment bug which is why stack vars
// are moved into locals
func:int open(str, int, int) {
    let fd, flags, mode;
    fd cast_int flags mode ~[3] SYS_OPEN syscall
    return
}

func close(int) {
    let fd;
    fd ~[1] SYS_CLOSE syscall drop
}

func stat(str, int) {
    let filename, statbuf;
    filename cast_int statbuf ~[2] SYS_STAT syscall drop
}

func fstat(int, int) {
    let fd, statbuf;
    fd statbuf ~[2] SYS_FSTAT syscall drop
}

func exit(int) {
    ~[1] SYS_EXIT syscall drop
}
