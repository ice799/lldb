//===-- RegisterContext_x86_64.cpp ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Target/X86/RegisterContext_x86_64.h"

using namespace lldb_private;

RegisterContext_x86_64::RegisterContext_x86_64(Thread &thread,
                                               StackFrame *frame)
    : RegisterContext(thread, frame)
{
}

uint32_t
RegisterContext_x86_64::ConvertRegisterKindToRegisterNumber(uint32_t kind,
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
            return LLDB_INVALID_REGNUM;
        }
    }

    return LLDB_INVALID_REGNUM;
}

size_t
RegisterContext_x86_64::GetRegisterCount()
{
    return k_num_registers;
}

size_t
RegisterContext_x86_64::GetRegisterSetCount()
{
    return k_num_generic_register_sets;
}

const lldb::RegisterSet *
RegisterContext_x86_64::GetRegisterSet(uint32_t set)
{
    if (set < k_num_generic_register_sets)
        return &g_reg_sets[set];
    return NULL;
}

//------------------------------------------------------------------------------
// Static RegisterSet data.

const lldb::RegisterSet 
RegisterContext_x86_64::g_reg_sets[k_num_generic_register_sets] =
{
    { "General Purpose Registers", "gpr", k_num_gpr_registers, g_gpr_regnums },
    { "Floating Point Registers",  "fpu", k_num_fpu_registers, g_fpu_regnums }
};

const uint32_t
RegisterContext_x86_64::g_gpr_regnums[k_num_gpr_registers] =
{
    gpr_rax,
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
    gpr_gs
};

const uint32_t 
RegisterContext_x86_64::g_fpu_regnums[k_num_fpu_registers] =
{
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
    fpu_xmm15
};
