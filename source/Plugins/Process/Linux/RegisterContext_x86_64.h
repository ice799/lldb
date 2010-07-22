//===-- RegisterContext_x86_64.h --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContext_x86_64_H_
#define liblldb_RegisterContext_x86_64_H_

#include "RegisterContextLinux.h"

class ProcessMonitor;

class RegisterContext_x86_64
    : public RegisterContextLinux
{
public:
    RegisterContext_x86_64(lldb_private::Thread &thread,
                           lldb_private::StackFrame *frame);

    ~RegisterContext_x86_64();

    void
    Invalidate();

    size_t
    GetRegisterCount();

    const lldb::RegisterInfo *
    GetRegisterInfoAtIndex(uint32_t reg);

    size_t
    GetRegisterSetCount();

    const lldb::RegisterSet *
    GetRegisterSet(uint32_t set);

    bool
    ReadRegisterValue(uint32_t reg, lldb_private::Scalar &value);

    bool
    ReadRegisterBytes(uint32_t reg, lldb_private::DataExtractor &data);

    bool
    ReadAllRegisterValues(lldb::DataBufferSP &data_sp);

    bool
    WriteRegisterValue(uint32_t reg, const lldb_private::Scalar &value);

    bool
    WriteRegisterBytes(uint32_t reg, lldb_private::DataExtractor &data,
                       uint32_t data_offset = 0);

    bool
    WriteAllRegisterValues(const lldb::DataBufferSP &data_sp);

    uint32_t
    ConvertRegisterKindToRegisterNumber(uint32_t kind, uint32_t num);

    bool
    HardwareSingleStep(bool enable);

    bool
    UpdateAfterBreakpoint();

    struct GPR
    {
        uint64_t r15;
        uint64_t r14;
        uint64_t r13;
        uint64_t r12;
        uint64_t rbp;
        uint64_t rbx;
        uint64_t r11;
        uint64_t r10;
        uint64_t r9;
        uint64_t r8;
        uint64_t rax;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rsi;
        uint64_t rdi;
        uint64_t orig_ax;
        uint64_t rip;
        uint64_t cs;
        uint64_t flags;
        uint64_t rsp;
        uint64_t ss;
        uint64_t fs_base;
        uint64_t gs_base;
        uint64_t ds;
        uint64_t es;
        uint64_t fs;
        uint64_t gs;
    };

    struct MMSReg
    {
        uint8_t bytes[10];
        uint8_t pad[6];
    };

    struct XMMReg
    {
        uint8_t bytes[16];
    };

    struct FPU
    {
        uint16_t cwd;
        uint16_t swd;
        uint16_t twd;
        uint16_t fop;
        uint64_t rip;
        uint64_t rdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        MMSReg   st_space[8];
        XMMReg   xmm_space[16];
        uint32_t padding[24];
    };

    struct UserArea
    {
        GPR regs;
        int u_fpvalid;
        int pad0;
        FPU i387;
        unsigned long int u_tsize;
        unsigned long int u_dsize;
        unsigned long int u_ssize;
        unsigned long start_code;
        unsigned long start_stack;
        long int signal;
        int reserved;
        int pad1;
        unsigned long u_ar0;
        FPU *u_fpstate;
        unsigned long magic;
        char u_comm[32];
        unsigned long u_debugreg[8];
        unsigned long error_code;
        unsigned long fault_address;
    };

private:
    UserArea user;

    ProcessMonitor &GetMonitor();
};

#endif // #ifndef liblldb_RegisterContext_x86_64_H_
