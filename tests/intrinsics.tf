import linux
import panic

macro assertion_failed {
    1 "Assertion failed, " 18 write!
}

func main() {
    // drop
    483 387 drop 483 != if {
        assertion_failed!
        panic!
    }

    // swap
    4783 34783 swap 4783 != swap 34783 != || if {
        assertion_failed!
        panic!
    }

    // dup
    34783 dup 34783 != swap 34783 != || if {
        assertion_failed!
        panic!
    }

    // over
    3829 6950 over 3829 != swap 6950 != || if {
        assertion_failed!
        panic!
    } drop

    // rot
    2738 35784337 348738 rot 2738 != swap 348738 != || swap 35784337 != || if {
        assertion_failed!
        panic!
    }

    // mem
    mem 0 == if {
        assertion_failed!
        panic!
    }

    // cast_int
    4.283 cast_int 4 != if {
        assertion_failed!
        panic!
    }
    428.9999 cast_int 428 != if {
        assertion_failed!
        panic!
    }

    // cast_str
    // this intrinsic does nothing
    mem cast_str cast_int mem != if {
        assertion_failed!
        panic!
    }

    // cast_float
    // TODO: `==` and `!=` doesn't work on floats
    482 cast_float cast_int 482 != if {
        assertion_failed!
        panic!
    }

    // read8
    10 let val;
    &val read8 10 != if {
        assertion_failed!
        panic!
    }
    255 let u8_max;
    &u8_max read8 255 != if {
        assertion_failed!
        panic!
    }
    3483 let val3;
    &val3 read8 255 > if {
        assertion_failed!
        panic!
    }

    // read64
    &val read64 10 != if {
        assertion_failed!
        panic!
    }
    &u8_max read64 255 != if {
        assertion_failed!
        panic!
    }
    &val3 read64 3483 != if {
        assertion_failed!
        panic!
    }
    18446744073709551615 let u64_max;
    &u64_max read64 18446744073709551615 != if {
        assertion_failed!
        panic!
    }

    // write8
    &val 69 write8
    &val read64 69 != if {
        assertion_failed!
        panic!
    }
    0 let val4;
    &val4 75485 write8
    &val4 read64 221 != if {
        assertion_failed!
        panic!
    }
    &u8_max 255 write8
    &u8_max read64 255 != if {
        assertion_failed!
        panic!
    }

    // write64
    &u64_max 18446744073709551615 write64
    &u64_max read64 18446744073709551615 != if {
        assertion_failed!
        panic!
    }
}
