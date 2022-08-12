import linux


// memory allocation using mmap :kekw:
//
// # Arguments
//
// * `int` - size of the chunk
//
// # Return value
//
// * `int` - pointer to the beginning of the allocated chunk
func __tf_alloc(i64) -> i64 {
    let len;
    0 len 3 34 0 0 ~[6] SYS_MMAP syscall
    return
}


// re-allocating a pre-allocated chunk
//
// # Arguments
//
// * `int` - pointer to the chunk
// * `int` - old size of the chunk
// * `int` - new size of the chunk
//
// # Return value
//
// * `int` - pointer to the re-allocated chunk
func __tf_realloc(i64, i64, i64) -> i64 {
    let old_addr, old_size, new_size;
    old_addr old_size new_size 0 ~[4] SYS_MREMAP syscall
    return
}


// deallocation of memory allocated by using `__tf_alloc()`
//
// # Arguments
//
// * `int` - addr to the pointer
// * `int` - len of the chunk
func __tf_dealloc(i64, i64) {
    let addr, len;
    addr len ~[2] SYS_MUNMAP syscall drop
}
