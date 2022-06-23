import linux
import panic

macro assertion_failed {
    1 "Assertion failed, " 18 write!
}

func:int foo() {
    69 return
}

func main() {
    0 let count;
    0 while dup 10 < do {
        dup 10 < over 0 > || if {
            &count over count + write64
            1 +
        } else {
            assertion_failed!
            panic!
        }
    } drop
    count 45 != if {
        assertion_failed!
        panic!
    }

    foo() 69 != if {
        assertion_failed!
        panic!
    }
}
