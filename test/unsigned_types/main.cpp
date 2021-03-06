//===-- main.cpp ------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
int main (int argc, char const *argv[])
{
    typedef unsigned int uint32_t;
    unsigned char the_unsigned_char = 'c';
    unsigned short the_unsigned_short = 'c';
    unsigned int the_unsigned_int = 'c';
    unsigned long the_unsigned_long = 'c';
    unsigned long long the_unsigned_long_long = 'c';
    uint32_t the_uint32 = 'c';

    return  the_unsigned_char - the_unsigned_short +
            the_unsigned_int - the_unsigned_long +
            the_unsigned_long_long - the_uint32;
}
