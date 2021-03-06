//===-- main.c --------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
int main (int argc, char const *argv[])
{
    struct point_tag {
        int x;
        int y;
    };

    struct rect_tag {
        struct point_tag bottom_left;
        struct point_tag top_right;
    };
    struct point_tag pt = { 2, 3 };
    struct rect_tag rect = {{1,2}, {3,4}};
    return 0;
}
