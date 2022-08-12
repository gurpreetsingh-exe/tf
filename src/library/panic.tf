import linux
import std

func number_to_mem(int) -> int {
    let number;
    0 while number 0 != do {
        dup mem 512 + swap - number 10 % 48 + write8
        &number number 10 / write64
        1 +
    }
    return
}

macro loc_fmt {
    1 here over over

    read64 number_to_mem()
    dup mem 513 + swap - swap
    mem 513 + 58 write8 1 + write!

    8 + read64 number_to_mem()
    dup mem 513 + swap - swap write!
}

macro panic {
    1 "panic at " 9 write! loc_fmt!
    1 "\n" 1 write!
    101 exit!
}
