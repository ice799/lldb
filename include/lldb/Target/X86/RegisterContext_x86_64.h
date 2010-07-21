//===-- RegisterContext_x86_64.cpp ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContext_x86_64_H_
#define liblldb_RegisterContext_x86_64_H_

#include "lldb/Target/RegisterContext.h"

namespace lldb_private {

//------------------------------------------------------------------------------
/// @class RegisterContext_x86_64
/// @brief Parital specialization for x86_64 RegisterContext implementations.
///
/// This class provides generic register number definitions and RegisterSet
/// entries for the x86_64 platform.  Specific platform plugins can further
/// refine this class to provide complete support for their respective platform.
class RegisterContext_x86_64
    : public lldb_private::RegisterContext
{
public:
    RegisterContext_x86_64(lldb_private::Thread &thread,
                           lldb_private::StackFrame *frame);

    /// Converts a generic LLDB register kind and number to the corresponding
    /// X86_64RegNum value, or LLDB_INVALID_REGNUM if there is no
    /// correspondence.
    uint32_t
    ConvertRegisterKindToRegisterNumber(uint32_t kind, uint32_t num);

protected:
    /// The generic implementation provides definitions for the GPR and FPU
    /// register sets (the latter includes MMX and XMM registers).  The
    /// following constant defines the number of default sets supported.  If a
    /// subclass wishes to provided additional register sets it may allocate
    /// indices above this value.
    enum {
        k_num_generic_register_sets = 2
    };

public:
    /// Returns the total number of registers contained in the default register
    /// sets.  May be extended by subclasses.
    virtual size_t
    GetRegisterCount();

    /// Default implementation returns k_num_generic_register_sets.  May be
    /// extended by subclasses.
    virtual size_t
    GetRegisterSetCount();

    /// Returns a generic register set.  May be extended by subclasses.
    virtual const lldb::RegisterSet *
    GetRegisterSet(uint32_t set);

    //------------------------------------------------------------------
    // x86_64 register names.
    //------------------------------------------------------------------
    enum X86_64RegNumber
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

        k_num_gpr_registers,
        
        fpu_fcw = k_num_gpr_registers,
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
        k_num_fpu_registers = k_num_registers - k_num_gpr_registers,
        
        // Aliases
        fpu_fctrl = fpu_fcw,
        fpu_fstat = fpu_fsw,
        fpu_ftag  = fpu_ftw,
        fpu_fiseg = fpu_cs,
        fpu_fioff = fpu_ip,
        fpu_foseg = fpu_ds,
        fpu_fooff = fpu_dp
    };

    //------------------------------------------------------------------
    // GDB register names.
    //------------------------------------------------------------------
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

    //------------------------------------------------------------------
    // GCC DWARF register names.
    //------------------------------------------------------------------
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

protected:
    static const lldb::RegisterSet g_reg_sets[k_num_generic_register_sets];
    static const uint32_t g_gpr_regnums[k_num_gpr_registers];
    static const uint32_t g_fpu_regnums[k_num_fpu_registers];
};

} // End lldb_private namesapce.

#endif // #ifndef liblldb_RegisterContext_x86_64_H_
