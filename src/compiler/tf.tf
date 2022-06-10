import std


// token types supported by tf-lang
const TOKEN_NUMBER 1


// memory allocation using mmap :kekw:
//
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
func:int __tf_realloc(int, int, int) {
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
func __tf_dealloc(int, int) {
    let addr, len;
    addr len ~[2] SYS_MUNMAP syscall drop
}


// check if the given character is a digit (0-9)
//
// # Arguments
//
// * `int` - character (a u8 but that type doesn't exist so...)
//
// # Return value
//
// * `bool` - `true` if the character was a digit and `false` otherwise
func:bool is_num(int) {
    let num;
    num 47 > num 58 < && if {
        true return
    }
    false return
}


// lex string buffer into list of tokens
//
// # Arguments
//
// * `int` - pointer to the string buffer
// * `int` - length of the string buffer
//
// # Return
//
// * `int` - pointer to the `token_list` struct
func:int lex_tokens(int, int) {
    let buf, length;

    // buffer to collect all the words in
    128 __tf_alloc() let token_buf;

    // token list holds the list of pointers to the tokens
    // this list is supposed to be dynamic and expandable
    //
    // # Fields
    //
    // * (u64) `size`   - offset(0)  - size of the list
    // * (u64) `tokens` - offset(64) - beginning of the list of tokens
    128 __tf_alloc() let token_list;

    0 let id;
    0 let word_len;
    id while id length < do {
        id buf + read8 let curr_char;
        &word_len 0 write64
        curr_char 47 > curr_char 58 < && if {
            id let token_start;
            while curr_char 47 > curr_char 58 < && do {
                token_buf word_len + curr_char write8
                &word_len word_len 1 + write64
                &id id 1 + write64
                &curr_char id buf + read8 write8
            }
            // allocate 80 bytes for token, this might become 80 to store the type
            //
            // # Fields
            //
            // * (u8)  `type`   - offset(0)  - type of the token
            // * (u64) `start`  - offset(8)  - index `id` where the word starts in the buffer
            // * (u8)  `length` - offset(72) - token len
            80 __tf_alloc() let token;
            token TOKEN_NUMBER write8
            token 8 + token_start write64
            token 72 + word_len write8

            // append the token into the `token_list` and update size
            token_list read64 let prev_len;
            token_list 64 + prev_len 64 * + token write64
            token_list prev_len 1 + write64

            // allocate more space for the next token
            prev_len 1 + 64 * 64 + let old_size;
            token_list old_size old_size 64 + __tf_realloc()
            &token_list swap write64
        }
        curr_char 32 == curr_char 10 == || if {
            &id id 1 + write64
        } else {
            &id id 1 + write64
        }
    } drop

    token_buf 128 __tf_dealloc()
    token_list
    return
}


// reads file and loads the contents into memory
//
// # Arguments
//
// * `str` - path of the file
//
// # Return
//
// * `int` - pointer to the `program` struct
func:int read_file(str) {
    // get file descriptor to read the file
    O_RDONLY 0 open! let fd;

    // allocate statbuf to get size of file
    STATBUF_SIZE __tf_alloc() let statbuf;
    fd statbuf fstat!

    // 48 is the offset to st_size field
    statbuf 48 + read64 let filesize;
    statbuf STATBUF_SIZE __tf_dealloc()

    filesize __tf_alloc() let buf;
    fd buf filesize read! filesize != if {
        "Error when reading file\n" println()
        1 exit!
    }

    // close the file
    fd close!

    // `program` holds the info about the source file and it's contents
    //
    // # Fields
    //
    // * (u64) `buf`  - offset(0)  - pointer to the char list
    // * (u64) `size` - offset(64) - length of `buf`
    128 __tf_alloc() let program;
    program buf write64
    program 64 + filesize write64

    program
    return
}


// parse tokens into IR
//
// # Arguments
//
// * `int` - pointer to `token_list` struct
// * `int` - pointer to `program` struct
func gen_ir(int, int) {
    let token_list, program;
    token_list read64 let ntokens;
    program read64 let buf;

    0 let acc;
    while acc ntokens < do {
        token_list 64 + acc 64 * + read64 let token;
        token 72 + read8 let tok_len;
        0 let i;
        i while i tok_len < do {
            i token 8 + read64 + buf swap + read8
            i mem + swap write8
            &i i 1 + write64
        } drop
        mem tok_len + 10 write8
        1 mem tok_len 1 + write!
        &acc acc 1 + write64
    }
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
        1 exit!
    }

    // read filepath from *argv and write contents of file into `program.buf`
    argv 16 + read64 cast_str read_file() let program;
    program read64 let buf;
    program 64 + read64 let filesize;

    buf filesize lex_tokens() let token_list;

    token_list program gen_ir()
    token_list read64 let ntokens;

    token_list ntokens 64 * 64 + __tf_dealloc()
    buf filesize __tf_dealloc()
    program 128 __tf_dealloc()

    0 exit!
}
