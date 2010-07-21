//===-- RegisterContextLinux_x86_64.cpp -------------------------*- C++ -*-===//
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


static unsigned 
GetRegOffset(unsigned reg)
{
    assert(reg < RegisterContext_x86_64::k_num_registers && 
           "Invalid register number.");
    return g_register_offsets[reg];
}

RegisterContextLinux_x86_64::RegisterContextLinux_x86_64(Thread &thread,
                                                         StackFrame *frame)
 : RegisterContext_x86_64(thread, frame)
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

const lldb::RegisterInfo *
RegisterContextLinux_x86_64::GetRegisterInfoAtIndex(uint32_t reg)
{
    return NULL;
}

bool
RegisterContextLinux_x86_64::ReadRegisterValue(uint32_t reg,
                                               Scalar &value)
{
    return GetMonitor().ReadRegisterValue(GetRegOffset(reg), value);
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
    return GetMonitor().WriteRegisterValue(GetRegOffset(reg), value);
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

bool
RegisterContextLinux_x86_64::HardwareSingleStep(bool enable)
{
    return GetMonitor().SingleStep(GetThreadID());
}
