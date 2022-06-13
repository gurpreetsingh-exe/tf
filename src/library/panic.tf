import linux
import std

func:int number_to_mem(int) {
    let number;
    0 while number 0 != do {
        dup mem 514 + swap - number 10 % 48 + write8
        &number number 10 / write64
        1 +
    }
    return
}

macro loc_fmt {
    1 here over over

    read64 number_to_mem()
    mem 512 + swap

    dup mem 513 + + 58 write64 2 +
    write!

    8 + read64 number_to_mem()
    mem 513 + swap 1 + write!
}

macro panic {
    1 "panic at " 9 write! loc_fmt!
    1 "\n" 1 write!
    101 exit!
}
