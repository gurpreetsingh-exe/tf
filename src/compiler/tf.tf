import std


// memory allocation using mmap :kekw:
// # Arguments
//
// * `int` - size of the chunk
//
// # Return value
//
// * `int` - pointer to the beginning of the allocated chunk
func:int __tf_alloc(int) {
    let len;
    0 len 3 34 0 0 ~[6] SYS_MMAP syscall
    return
}


// deallocation of memory allocated by using `__tf_alloc()`
// # Arguments
//
// * `int` - addr to the pointer
// * `int` - len of the chunk
func __tf_dealloc(int, int) {
    let addr, len;
    addr len ~[2] SYS_MUNMAP syscall drop
}


// reads file and loads the contents into memory
//
// # Arguments
//
// * `str` - path of the file
func read_file(str) {
    // get file descriptor to read the file
    O_RDONLY 0 open() let fd;

    // allocate statbuf to get size of file
    STATBUF_SIZE __tf_alloc() let statbuf;
    fd statbuf fstat()

    // 48 is the offset to st_size field
    statbuf 48 + read64 let filesize;
    statbuf STATBUF_SIZE __tf_dealloc()

    filesize __tf_alloc() let buf;
    fd buf filesize read() filesize != if {
        "Error when reading file\n" println()
        1 exit()
    }

    // close the file
    fd close()

    buf cast_str println()
    buf filesize __tf_dealloc()
}


// main function of the compiler
//
// # Arguments
//
// * `int` - command-line arguments
func main(int) {
    let argv;
    argv read64 2 < if {
        "Usage: tf file...\n" println()
        1 exit()
    }

    // read filepath from *argv
    argv 16 + read64 cast_str read_file()
    0 exit()
}
