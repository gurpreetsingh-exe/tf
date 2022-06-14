import linux
import std
import panic


// token types supported by tf-lang
// literals
const TOKEN_NUMBER 1

// `+`
const TOKEN_PLUS 2


// IR node types
const PUSH_INT 1
const BINARY_ADD 2


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


// allocate 80 bytes for token, this might become 80 to store the type
//
// # Fields
//
// * (u8)  `type`   - offset(0)  - type of the token
// * (u64) `start`  - offset(8)  - index `id` where the word starts in the buffer
// * (u8)  `length` - offset(72) - token len
macro new_token {
    let len, start, typ;
    80 __tf_alloc() let token;

    token typ write8
    token 8 + start write64
    token 72 + len write8
}


// append the token into the `token_list` and update size
macro append_token {
    token_list read64 let prev_len;
    token_list 64 + prev_len 64 * + token write64
    token_list prev_len 1 + write64

    // allocate more space for the next token
    prev_len 1 + 64 * 64 + let old_size;
    token_list old_size old_size 64 + __tf_realloc()
    &token_list swap write64
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

            TOKEN_NUMBER token_start word_len new_token!
            append_token!
        } else {
            curr_char 43 == if {
                TOKEN_PLUS id 1 new_token!
                append_token!

                &id id 1 + write64
            } else {
                curr_char 32 == curr_char 10 == || if {
                    &id id 1 + write64
                } else {
                    "ERROR: Unexpected character" println()
                    1 exit!
                }
            }
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


// allocate 72 bytes for IR node
//
// # Fields
//
// * (u8)  `type`   - offset(0)  - type of the node
// * (u64) `value`  - offset(8)  - pointer to the node
macro new_ir_node {
    let value, typ;
    72 __tf_alloc() let node;

    node typ write8
    node 8 + value write64
}


// append node into the ir_list
macro append_ir {
    ir_list read64 let prev_len;
    ir_list 64 + prev_len 64 * + node write64
    ir_list prev_len 1 + write64

    // allocate more space for the next node
    prev_len 1 + 64 * 64 + let old_size;
    ir_list old_size old_size 64 + __tf_realloc()
    &ir_list swap write64
}


// parse tokens into IR
//
// # Arguments
//
// * `int` - pointer to `token_list` array
// * `int` - pointer to `program` struct
// * `int` - pointer to `ir_list` array
func gen_ir(int, int, int) {
    let token_list, program, ir_list;
    token_list read64 let ntokens;
    program read64 let buf;

    0 let acc;
    while acc ntokens < do {
        token_list 64 + acc 64 * + read64 let token;
        token read8 let token_kind;
        token_kind TOKEN_NUMBER == if {
            PUSH_INT 0 new_ir_node!
            append_ir!
        }
        token_kind TOKEN_PLUS == if {
            BINARY_ADD 0 new_ir_node!
            append_ir!
        }
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

    // ir_list holds the list of pointers to the ir node types
    // this list is supposed to be dynamic and expandable
    //
    // # Fields
    //
    // * (u64) `size`  - offset(0)  - size of the list
    // * (u64) `nodes` - offset(64) - beginning of the list of nodes
    128 __tf_alloc() let ir_list;

    token_list program ir_list gen_ir()
    token_list read64 let ntokens;

    token_list ntokens 64 * 64 + __tf_dealloc()
    ir_list dup read64 64 * 64 + __tf_dealloc()
    buf filesize __tf_dealloc()
    program 128 __tf_dealloc()

    0 exit!
}
