//===-- RegisterContext_x86_64.cpp ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <cstring>
#include <errno.h>
#include <stdint.h>

#include "lldb/Core/Scalar.h"
#include "lldb/Target/Thread.h"

#include "ProcessLinux.h"
#include "ProcessMonitor.h"
#include "RegisterContextLinux_x86_64.h"

using namespace lldb_private;

enum
{
    gpr_rax = 0,
    gpr_rbx,
    gpr_rcx,
    gpr_rdx,
    gpr_rdi,
    gpr_rsi,
    gpr_rbp,
    gpr_rsp,
    gpr_r8,
    gpr_r9,
    gpr_r10,
    gpr_r11,
    gpr_r12,
    gpr_r13,
    gpr_r14,
    gpr_r15,
    gpr_rip,
    gpr_rflags,
    gpr_cs,
    gpr_fs,
    gpr_gs,

    fpu_fcw,
    fpu_fsw,
    fpu_ftw,
    fpu_fop,
    fpu_ip,
    fpu_cs,
    fpu_dp,
    fpu_ds,
    fpu_mxcsr,
    fpu_mxcsrmask,
    fpu_stmm0,
    fpu_stmm1,
    fpu_stmm2,
    fpu_stmm3,
    fpu_stmm4,
    fpu_stmm5,
    fpu_stmm6,
    fpu_stmm7,
    fpu_xmm0,
    fpu_xmm1,
    fpu_xmm2,
    fpu_xmm3,
    fpu_xmm4,
    fpu_xmm5,
    fpu_xmm6,
    fpu_xmm7,
    fpu_xmm8,
    fpu_xmm9,
    fpu_xmm10,
    fpu_xmm11,
    fpu_xmm12,
    fpu_xmm13,
    fpu_xmm14,
    fpu_xmm15,

    k_num_registers,

    // Aliases
    fpu_fctrl = fpu_fcw,
    fpu_fstat = fpu_fsw,
    fpu_ftag  = fpu_ftw,
    fpu_fiseg = fpu_cs,
    fpu_fioff = fpu_ip,
    fpu_foseg = fpu_ds,
    fpu_fooff = fpu_dp
};

// Computes the offset of the given GPR in the user data area.
#define GPR_OFFSET(regname) \
    (offsetof(RegisterContextLinux_x86_64::UserArea, regs) + \
     offsetof(RegisterContextLinux_x86_64::GPR, regname))

// Computes the offset of the given FPR in the user data area.
#define FPR_OFFSET(regname) \
    (offsetof(RegisterContextLinux_x86_64::UserArea, i387) + \
     offsetof(RegisterContextLinux_x86_64::FPU, regname))

// The following lookup table converts register numbers to offsets in the user
// area.
static unsigned g_register_offsets[] =
{
    GPR_OFFSET(rax),            // gpr_rax
    GPR_OFFSET(rbx),            // gpr_rbx
    GPR_OFFSET(rcx),            // gpr_rcx
    GPR_OFFSET(rdx),            // gpr_rdx
    GPR_OFFSET(rdi),            // gpr_rdi
    GPR_OFFSET(rsi),            // gpr_rsi
    GPR_OFFSET(rbp),            // gpr_rbp
    GPR_OFFSET(rsp),            // gpr_rsp
    GPR_OFFSET(r8),             // gpr_r8
    GPR_OFFSET(r9),             // gpr_r9
    GPR_OFFSET(r10),            // gpr_r10
    GPR_OFFSET(r11),            // gpr_r11
    GPR_OFFSET(r12),            // gpr_r12
    GPR_OFFSET(r13),            // gpr_r13
    GPR_OFFSET(r14),            // gpr_r14
    GPR_OFFSET(r15),            // gpr_r15
    GPR_OFFSET(rip),            // gpr_rip
    GPR_OFFSET(flags),          // gpr_rflags
    GPR_OFFSET(cs),             // gpr_cs
    GPR_OFFSET(fs),             // gpr_fs
    GPR_OFFSET(gs),             // gpr_gs

    FPR_OFFSET(cwd),            // fpu_fcw
    FPR_OFFSET(swd),            // fpu_fsw
    FPR_OFFSET(twd),            // fpu_ftw
    FPR_OFFSET(fop),            // fpu_fop
    FPR_OFFSET(rip),            // fpu_ip
    FPR_OFFSET(rip),            // fpu_cs FIXME: Extract segment from rip.
    FPR_OFFSET(rdp),            // fpu_dp
    FPR_OFFSET(rdp),            // fpu_ds FIXME: Extract segment from rdp.
    FPR_OFFSET(mxcsr),          // fpu_mxcsr
    FPR_OFFSET(mxcsr_mask),     // fpu_mxcsrmask

    FPR_OFFSET(st_space[0]),    // fpu_stmm0
    FPR_OFFSET(st_space[1]),    // fpu_stmm1
    FPR_OFFSET(st_space[2]),    // fpu_stmm2
    FPR_OFFSET(st_space[3]),    // fpu_stmm3
    FPR_OFFSET(st_space[4]),    // fpu_stmm4
    FPR_OFFSET(st_space[5]),    // fpu_stmm5
    FPR_OFFSET(st_space[6]),    // fpu_stmm6
    FPR_OFFSET(st_space[7]),    // fpu_stmm7
    FPR_OFFSET(xmm_space[0]),   // fpu_xmm0
    FPR_OFFSET(xmm_space[1]),   // fpu_xmm1
    FPR_OFFSET(xmm_space[2]),   // fpu_xmm2
    FPR_OFFSET(xmm_space[3]),   // fpu_xmm3
    FPR_OFFSET(xmm_space[4]),   // fpu_xmm4
    FPR_OFFSET(xmm_space[5]),   // fpu_xmm5
    FPR_OFFSET(xmm_space[6]),   // fpu_xmm6
    FPR_OFFSET(xmm_space[7]),   // fpu_xmm7
    FPR_OFFSET(xmm_space[8]),   // fpu_xmm8
    FPR_OFFSET(xmm_space[9]),   // fpu_xmm9
    FPR_OFFSET(xmm_space[10]),  // fpu_xmm10
    FPR_OFFSET(xmm_space[11]),  // fpu_xmm11
    FPR_OFFSET(xmm_space[12]),  // fpu_xmm12
    FPR_OFFSET(xmm_space[13]),  // fpu_xmm13
    FPR_OFFSET(xmm_space[14]),  // fpu_xmm14
    FPR_OFFSET(xmm_space[15])   // fpu_xmm15
};

enum gcc_dwarf_regnums
{
    gcc_dwarf_gpr_rax = 0,
    gcc_dwarf_gpr_rdx,
    gcc_dwarf_gpr_rcx,
    gcc_dwarf_gpr_rbx,
    gcc_dwarf_gpr_rsi,
    gcc_dwarf_gpr_rdi,
    gcc_dwarf_gpr_rbp,
    gcc_dwarf_gpr_rsp,
    gcc_dwarf_gpr_r8,
    gcc_dwarf_gpr_r9,
    gcc_dwarf_gpr_r10,
    gcc_dwarf_gpr_r11,
    gcc_dwarf_gpr_r12,
    gcc_dwarf_gpr_r13,
    gcc_dwarf_gpr_r14,
    gcc_dwarf_gpr_r15,
    gcc_dwarf_gpr_rip,
    gcc_dwarf_fpu_xmm0,
    gcc_dwarf_fpu_xmm1,
    gcc_dwarf_fpu_xmm2,
    gcc_dwarf_fpu_xmm3,
    gcc_dwarf_fpu_xmm4,
    gcc_dwarf_fpu_xmm5,
    gcc_dwarf_fpu_xmm6,
    gcc_dwarf_fpu_xmm7,
    gcc_dwarf_fpu_xmm8,
    gcc_dwarf_fpu_xmm9,
    gcc_dwarf_fpu_xmm10,
    gcc_dwarf_fpu_xmm11,
    gcc_dwarf_fpu_xmm12,
    gcc_dwarf_fpu_xmm13,
    gcc_dwarf_fpu_xmm14,
    gcc_dwarf_fpu_xmm15,
    gcc_dwarf_fpu_stmm0,
    gcc_dwarf_fpu_stmm1,
    gcc_dwarf_fpu_stmm2,
    gcc_dwarf_fpu_stmm3,
    gcc_dwarf_fpu_stmm4,
    gcc_dwarf_fpu_stmm5,
    gcc_dwarf_fpu_stmm6,
    gcc_dwarf_fpu_stmm7
};

enum gdb_regnums
{
    gdb_gpr_rax     =   0,
    gdb_gpr_rbx     =   1,
    gdb_gpr_rcx     =   2,
    gdb_gpr_rdx     =   3,
    gdb_gpr_rsi     =   4,
    gdb_gpr_rdi     =   5,
    gdb_gpr_rbp     =   6,
    gdb_gpr_rsp     =   7,
    gdb_gpr_r8      =   8,
    gdb_gpr_r9      =   9,
    gdb_gpr_r10     =  10,
    gdb_gpr_r11     =  11,
    gdb_gpr_r12     =  12,
    gdb_gpr_r13     =  13,
    gdb_gpr_r14     =  14,
    gdb_gpr_r15     =  15,
    gdb_gpr_rip     =  16,
    gdb_gpr_rflags  =  17,
    gdb_gpr_cs      =  18,
    gdb_gpr_ss      =  19,
    gdb_gpr_ds      =  20,
    gdb_gpr_es      =  21,
    gdb_gpr_fs      =  22,
    gdb_gpr_gs      =  23,
    gdb_fpu_stmm0   =  24,
    gdb_fpu_stmm1   =  25,
    gdb_fpu_stmm2   =  26,
    gdb_fpu_stmm3   =  27,
    gdb_fpu_stmm4   =  28,
    gdb_fpu_stmm5   =  29,
    gdb_fpu_stmm6   =  30,
    gdb_fpu_stmm7   =  31,
    gdb_fpu_fctrl   =  32,  gdb_fpu_fcw = gdb_fpu_fctrl,
    gdb_fpu_fstat   =  33,  gdb_fpu_fsw = gdb_fpu_fstat,
    gdb_fpu_ftag    =  34,  gdb_fpu_ftw = gdb_fpu_ftag,
    gdb_fpu_fiseg   =  35,  gdb_fpu_cs  = gdb_fpu_fiseg,
    gdb_fpu_fioff   =  36,  gdb_fpu_ip  = gdb_fpu_fioff,
    gdb_fpu_foseg   =  37,  gdb_fpu_ds  = gdb_fpu_foseg,
    gdb_fpu_fooff   =  38,  gdb_fpu_dp  = gdb_fpu_fooff,
    gdb_fpu_fop     =  39,
    gdb_fpu_xmm0    =  40,
    gdb_fpu_xmm1    =  41,
    gdb_fpu_xmm2    =  42,
    gdb_fpu_xmm3    =  43,
    gdb_fpu_xmm4    =  44,
    gdb_fpu_xmm5    =  45,
    gdb_fpu_xmm6    =  46,
    gdb_fpu_xmm7    =  47,
    gdb_fpu_xmm8    =  48,
    gdb_fpu_xmm9    =  49,
    gdb_fpu_xmm10   =  50,
    gdb_fpu_xmm11   =  51,
    gdb_fpu_xmm12   =  52,
    gdb_fpu_xmm13   =  53,
    gdb_fpu_xmm14   =  54,
    gdb_fpu_xmm15   =  55,
    gdb_fpu_mxcsr   =  56
};

static unsigned GetRegOffset(unsigned reg)
{
    assert(reg < k_num_registers && "Invalid register number.");
    return g_register_offsets[reg];
}

RegisterContextLinux_x86_64::RegisterContextLinux_x86_64(Thread &thread,
                                                         StackFrame *frame)
 : RegisterContext(thread, frame)
{
}

RegisterContextLinux_x86_64::~RegisterContextLinux_x86_64()
{
}

ProcessMonitor &
RegisterContextLinux_x86_64::GetMonitor()
{
    ProcessLinux *process = static_cast<ProcessLinux*>(CalculateProcess());
    return process->GetMonitor();
}

void
RegisterContextLinux_x86_64::Invalidate()
{
}

size_t
RegisterContextLinux_x86_64::GetRegisterCount()
{
    return 0;
}

const lldb::RegisterInfo *
RegisterContextLinux_x86_64::GetRegisterInfoAtIndex(uint32_t reg)
{
    return NULL;
}

size_t
RegisterContextLinux_x86_64::GetRegisterSetCount()
{
    return 0;
}

const lldb::RegisterSet *
RegisterContextLinux_x86_64::GetRegisterSet(uint32_t set)
{
    return NULL;
}

bool
RegisterContextLinux_x86_64::ReadRegisterValue(uint32_t reg,
                                               Scalar &value)
{
    ProcessMonitor &monitor = GetMonitor();
    return monitor.ReadRegisterValue(GetRegOffset(reg), value);
}

bool
RegisterContextLinux_x86_64::ReadRegisterBytes(uint32_t reg,
                                               DataExtractor &data)
{
    return false;
}

bool
RegisterContextLinux_x86_64::ReadAllRegisterValues(lldb::DataBufferSP &data_sp)
{
    return false;
}

bool
RegisterContextLinux_x86_64::WriteRegisterValue(uint32_t reg,
                                                const Scalar &value)
{
    ProcessMonitor &monitor = GetMonitor();
    return monitor.WriteRegisterValue(GetRegOffset(reg), value);
}

bool
RegisterContextLinux_x86_64::WriteRegisterBytes(uint32_t reg,
                                                DataExtractor &data,
                                                uint32_t data_offset)
{
    return false;
}

bool
RegisterContextLinux_x86_64::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp)
{
    return false;
}

uint32_t
RegisterContextLinux_x86_64::ConvertRegisterKindToRegisterNumber(uint32_t kind,
                                                                 uint32_t num)
{
    if (kind == lldb::eRegisterKindGeneric)
    {
        switch (num)
        {
        case LLDB_REGNUM_GENERIC_PC:    return gpr_rip;
        case LLDB_REGNUM_GENERIC_SP:    return gpr_rsp;
        case LLDB_REGNUM_GENERIC_FP:    return gpr_rbp;
        case LLDB_REGNUM_GENERIC_FLAGS: return gpr_rflags;
        case LLDB_REGNUM_GENERIC_RA:
        default:
            assert(false && "Unexpected generic register number!");
            return LLDB_INVALID_REGNUM;
        }
    }

    if (kind == lldb::eRegisterKindGCC || kind == lldb::eRegisterKindDWARF)
    {
        switch (num)
        {
        case gcc_dwarf_gpr_rax:  return gpr_rax;
        case gcc_dwarf_gpr_rdx:  return gpr_rdx;
        case gcc_dwarf_gpr_rcx:  return gpr_rcx;
        case gcc_dwarf_gpr_rbx:  return gpr_rbx;
        case gcc_dwarf_gpr_rsi:  return gpr_rsi;
        case gcc_dwarf_gpr_rdi:  return gpr_rdi;
        case gcc_dwarf_gpr_rbp:  return gpr_rbp;
        case gcc_dwarf_gpr_rsp:  return gpr_rsp;
        case gcc_dwarf_gpr_r8:   return gpr_r8;
        case gcc_dwarf_gpr_r9:   return gpr_r9;
        case gcc_dwarf_gpr_r10:  return gpr_r10;
        case gcc_dwarf_gpr_r11:  return gpr_r11;
        case gcc_dwarf_gpr_r12:  return gpr_r12;
        case gcc_dwarf_gpr_r13:  return gpr_r13;
        case gcc_dwarf_gpr_r14:  return gpr_r14;
        case gcc_dwarf_gpr_r15:  return gpr_r15;
        case gcc_dwarf_gpr_rip:  return gpr_rip;
        case gcc_dwarf_fpu_xmm0: return fpu_xmm0;
        case gcc_dwarf_fpu_xmm1: return fpu_xmm1;
        case gcc_dwarf_fpu_xmm2: return fpu_xmm2;
        case gcc_dwarf_fpu_xmm3: return fpu_xmm3;
        case gcc_dwarf_fpu_xmm4: return fpu_xmm4;
        case gcc_dwarf_fpu_xmm5: return fpu_xmm5;
        case gcc_dwarf_fpu_xmm6: return fpu_xmm6;
        case gcc_dwarf_fpu_xmm7: return fpu_xmm7;
        case gcc_dwarf_fpu_xmm8: return fpu_xmm8;
        case gcc_dwarf_fpu_xmm9: return fpu_xmm9;
        case gcc_dwarf_fpu_xmm10: return fpu_xmm10;
        case gcc_dwarf_fpu_xmm11: return fpu_xmm11;
        case gcc_dwarf_fpu_xmm12: return fpu_xmm12;
        case gcc_dwarf_fpu_xmm13: return fpu_xmm13;
        case gcc_dwarf_fpu_xmm14: return fpu_xmm14;
        case gcc_dwarf_fpu_xmm15: return fpu_xmm15;
        case gcc_dwarf_fpu_stmm0: return fpu_stmm0;
        case gcc_dwarf_fpu_stmm1: return fpu_stmm1;
        case gcc_dwarf_fpu_stmm2: return fpu_stmm2;
        case gcc_dwarf_fpu_stmm3: return fpu_stmm3;
        case gcc_dwarf_fpu_stmm4: return fpu_stmm4;
        case gcc_dwarf_fpu_stmm5: return fpu_stmm5;
        case gcc_dwarf_fpu_stmm6: return fpu_stmm6;
        case gcc_dwarf_fpu_stmm7: return fpu_stmm7;
        default:
            assert(false && "Unexpected DWARF register number!");
            return LLDB_INVALID_REGNUM;
        }
    }

    if (kind == lldb::eRegisterKindGDB)
    {
        switch (num)
        {
        case gdb_gpr_rax     : return gpr_rax;
        case gdb_gpr_rbx     : return gpr_rbx;
        case gdb_gpr_rcx     : return gpr_rcx;
        case gdb_gpr_rdx     : return gpr_rdx;
        case gdb_gpr_rsi     : return gpr_rsi;
        case gdb_gpr_rdi     : return gpr_rdi;
        case gdb_gpr_rbp     : return gpr_rbp;
        case gdb_gpr_rsp     : return gpr_rsp;
        case gdb_gpr_r8      : return gpr_r8;
        case gdb_gpr_r9      : return gpr_r9;
        case gdb_gpr_r10     : return gpr_r10;
        case gdb_gpr_r11     : return gpr_r11;
        case gdb_gpr_r12     : return gpr_r12;
        case gdb_gpr_r13     : return gpr_r13;
        case gdb_gpr_r14     : return gpr_r14;
        case gdb_gpr_r15     : return gpr_r15;
        case gdb_gpr_rip     : return gpr_rip;
        case gdb_gpr_rflags  : return gpr_rflags;
        case gdb_gpr_cs      : return gpr_cs;

        // FIXME: Just copy what is in "gs" for "ss", "ds" and "es" (for now).
        case gdb_gpr_ss      : return gpr_gs;
        case gdb_gpr_ds      : return gpr_gs;
        case gdb_gpr_es      : return gpr_gs;

        case gdb_gpr_fs      : return gpr_fs;
        case gdb_gpr_gs      : return gpr_gs;
        case gdb_fpu_stmm0   : return fpu_stmm0;
        case gdb_fpu_stmm1   : return fpu_stmm1;
        case gdb_fpu_stmm2   : return fpu_stmm2;
        case gdb_fpu_stmm3   : return fpu_stmm3;
        case gdb_fpu_stmm4   : return fpu_stmm4;
        case gdb_fpu_stmm5   : return fpu_stmm5;
        case gdb_fpu_stmm6   : return fpu_stmm6;
        case gdb_fpu_stmm7   : return fpu_stmm7;
        case gdb_fpu_fctrl   : return fpu_fctrl;
        case gdb_fpu_fstat   : return fpu_fstat;
        case gdb_fpu_ftag    : return fpu_ftag;
        case gdb_fpu_fiseg   : return fpu_fiseg;
        case gdb_fpu_fioff   : return fpu_fioff;
        case gdb_fpu_foseg   : return fpu_foseg;
        case gdb_fpu_fooff   : return fpu_fooff;
        case gdb_fpu_fop     : return fpu_fop;
        case gdb_fpu_xmm0    : return fpu_xmm0;
        case gdb_fpu_xmm1    : return fpu_xmm1;
        case gdb_fpu_xmm2    : return fpu_xmm2;
        case gdb_fpu_xmm3    : return fpu_xmm3;
        case gdb_fpu_xmm4    : return fpu_xmm4;
        case gdb_fpu_xmm5    : return fpu_xmm5;
        case gdb_fpu_xmm6    : return fpu_xmm6;
        case gdb_fpu_xmm7    : return fpu_xmm7;
        case gdb_fpu_xmm8    : return fpu_xmm8;
        case gdb_fpu_xmm9    : return fpu_xmm9;
        case gdb_fpu_xmm10   : return fpu_xmm10;
        case gdb_fpu_xmm11   : return fpu_xmm11;
        case gdb_fpu_xmm12   : return fpu_xmm12;
        case gdb_fpu_xmm13   : return fpu_xmm13;
        case gdb_fpu_xmm14   : return fpu_xmm14;
        case gdb_fpu_xmm15   : return fpu_xmm15;
        case gdb_fpu_mxcsr   : return fpu_mxcsr;
        default:
            assert(false && "Unexpected GDB register number!");
            return LLDB_INVALID_REGNUM;
        }
    }

    return LLDB_INVALID_REGNUM;
}

bool
RegisterContextLinux_x86_64::HardwareSingleStep(bool enable)
{
    return GetMonitor().SingleStep(GetThreadID());
}
