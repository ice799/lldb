//===-- main.cpp ------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

class A
{
public:
    A(int i=0):
        m_a_int(i),
        m_aa_int(i+1)
    {
    }

    //virtual
    ~A()
    {
    }

    int
    GetInteger() const
    {
        return m_a_int;
    }
    void
    SetInteger(int i)
    {
        m_a_int = i;
    }

protected:
    int m_a_int;
    int m_aa_int;
};

class B : public A
{
public:
    B(int ai, int bi) :
        A(ai),
        m_b_int(bi)
    {
    }

    //virtual
    ~B()
    {
    }

    int
    GetIntegerB() const
    {
        return m_b_int;
    }
    void
    SetIntegerB(int i)
    {
        m_b_int = i;
    }

protected:
    int m_b_int;
};


class C : public B
{
public:
    C(int ai, int bi, int ci) :
        B(ai, bi),
        m_c_int(ci)
    {
    }

    //virtual
    ~C()
    {
    }

    int
    GetIntegerC() const
    {
        return m_c_int;
    }
    void
    SetIntegerC(int i)
    {
        m_c_int = i;
    }

protected:
    int m_c_int;
};

int
main (int argc, char const *argv[])
{
    A a(12);
    B b(22,33);
    C c(44,55,66);
    return b.GetIntegerB() - a.GetInteger() + c.GetInteger();
}
