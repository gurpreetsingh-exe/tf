#define NULL 0

#define STDOUT 1

#define SYSCALL_WRITE 1

// Syscall wrapper functions
func write(fd, buf, size) {
    SYSCALL_WRITE fd buf size syscall3
}
