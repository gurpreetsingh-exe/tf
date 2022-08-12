const STDIN 0
const STDOUT 1
const STDERR 2

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
const O_WRONLY 1
const O_RDWR 2
const O_APPEND 1024
const O_CREAT 64

const STATBUF_SIZE 144

func string_len(str) -> i64 {
    let string;
    0 while dup string cast_int + read8 0 > do { 1+ }
    return
}

func println(str) {
    let string;
    string string_len() let length;
    string cast_int length + 10 write8 // add newline
    SYS_WRITE STDOUT string length 1 + ~[3] syscall ~[1]
}

func read(i64, i64, i64) -> i64 {
    let fd, buf, size;
    fd buf size ~[3] SYS_READ syscall
    return
}


func write(i64, str, i64) {
    let fd, buf, size;
    fd buf size ~[3] SYS_WRITE syscall drop
}


// TODO: there is a stack alignment bug which is why stack vars
// are moved into locals
func open(str, i64, i64) -> i64 {
    let fd, flags, mode;
    fd cast_int flags mode ~[3] SYS_OPEN syscall
    return
}


func close(i64) {
    let fd;
    fd ~[1] SYS_CLOSE syscall drop
}


func stat(str, i64) {
    let filename, statbuf;
    filename cast_int statbuf ~[2] SYS_STAT syscall drop
}


func fstat(i64, i64) {
    let fd, statbuf;
    fd statbuf ~[2] SYS_FSTAT syscall drop
}


func exit(i64) {
    ~[1] SYS_EXIT syscall drop
}


func rand() -> i64 {
    "/dev/urandom" 0 0 open! let fd;
    0 let a;
    fd &a 8 read! drop
    a
    return
}
