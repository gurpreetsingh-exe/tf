#define NULL 0

#define STDIN  0
#define STDOUT 1
#define STDERR 2

#define SYSCALL_WRITE 1

// Syscall wrapper functions
func write(fd, buf, size) {
    SYSCALL_WRITE fd buf size syscall3
}

// String helper functions
func strlen(string) {
    0 do {
        string @ drop
        1 +
    } dup string + @ NULL = 0 = while
    mem swap &
}

func printf(string) {
    STDOUT string strlen mem @ write
    drop drop drop
}
