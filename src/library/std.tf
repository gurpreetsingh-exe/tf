const STDIN 0
const STDOUT 1
const STDERR 2

const SYS_WRITE 1
const SYS_EXIT 60

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

func write(int, str, int) {
    ~[3] SYS_WRITE syscall drop
}

func exit(int) {
    ~[1] SYS_EXIT syscall drop
}
