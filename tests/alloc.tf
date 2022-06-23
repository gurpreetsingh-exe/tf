import linux
import alloc
import panic
import mod_assert

func main() {
    5000 __tf_alloc() let ptr;
    ptr 3574857 write64

    ptr read64 3574857 != if {
        assertion_failed!
        panic!
    }

    ptr 0 write64
    ptr read64 0 != if {
        assertion_failed!
        panic!
    }

    ptr 5000 __tf_dealloc()
}
