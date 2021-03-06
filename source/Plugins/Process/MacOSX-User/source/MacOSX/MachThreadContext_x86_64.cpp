//===-- MachThreadContext_x86_64.cpp ----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#if defined (__i386__) || defined (__x86_64__)

#include <sys/cdefs.h>

#include "lldb/Symbol/Function.h"
#include "lldb/Symbol/Symbol.h"

#include "MachThreadContext_x86_64.h"
#include "ProcessMacOSX.h"
#include "ThreadMacOSX.h"

using namespace lldb;
using namespace lldb_private;

MachThreadContext_x86_64::MachThreadContext_x86_64(ThreadMacOSX &thread) :
    MachThreadContext (thread),
    m_flags_reg(LLDB_INVALID_REGNUM)
{
}

MachThreadContext_x86_64::~MachThreadContext_x86_64()
{
}

MachThreadContext*
MachThreadContext_x86_64::Create(const ArchSpec &arch_spec, ThreadMacOSX &thread)
{
    return new MachThreadContext_x86_64(thread);
}

// Class init function
void
MachThreadContext_x86_64::Initialize()
{
    ArchSpec arch_spec("x86_64");
    ProcessMacOSX::AddArchCreateCallback(arch_spec, MachThreadContext_x86_64::Create);
}

// Instance init function
void
MachThreadContext_x86_64::InitializeInstance()
{
    RegisterContext *reg_ctx = m_thread.GetRegisterContext();
    assert (reg_ctx != NULL);
    m_flags_reg = reg_ctx->ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_FLAGS);
}

void
MachThreadContext_x86_64::ThreadWillResume()
{
    m_thread.GetRegisterContext()->HardwareSingleStep (m_thread.GetState() == eStateStepping);
}

bool
MachThreadContext_x86_64::ShouldStop()
{
    return true;
}

void
MachThreadContext_x86_64::RefreshStateAfterStop()
{
    m_thread.GetRegisterContext()->HardwareSingleStep (false);
}

bool
MachThreadContext_x86_64::NotifyException(MachException::Data& exc)
{
    switch (exc.exc_type)
    {
    case EXC_BAD_ACCESS:
        break;
    case EXC_BAD_INSTRUCTION:
        break;
    case EXC_ARITHMETIC:
        break;
    case EXC_EMULATION:
        break;
    case EXC_SOFTWARE:
        break;
    case EXC_BREAKPOINT:
        if (exc.exc_data.size() >= 2 && exc.exc_data[0] == 2)
        {
            RegisterContext *reg_ctx = m_thread.GetRegisterContext();
            assert (reg_ctx);
            lldb::addr_t pc = reg_ctx->GetPC(LLDB_INVALID_ADDRESS);
            if (pc != LLDB_INVALID_ADDRESS && pc > 0)
            {
                pc -= 1;
                reg_ctx->SetPC(pc);
            }
            return true;
        }
        break;
    case EXC_SYSCALL:
        break;
    case EXC_MACH_SYSCALL:
        break;
    case EXC_RPC_ALERT:
        break;
    }
    return false;
}


// Set the single step bit in the processor status register.
//kern_return_t
//MachThreadContext_x86_64::EnableHardwareSingleStep (bool enable)
//{
//  RegisterContext *reg_ctx = m_thread.GetRegisterContext();
//  assert (reg_ctx);
//  Scalar rflags_scalar;
//
//    if (reg_ctx->ReadRegisterValue (m_flags_reg, rflags_scalar))
//    {
//      Flags rflags(rflags_scalar.UInt());
//        const uint32_t trace_bit = 0x100u;
//        if (enable)
//      {
//          // If the trace bit is already set, there is nothing to do
//          if (rflags.IsSet (trace_bit))
//              return KERN_SUCCESS;
//            else
//              rflags.Set (trace_bit);
//      }
//        else
//      {
//          // If the trace bit is already cleared, there is nothing to do
//          if (rflags.IsClear (trace_bit))
//              return KERN_SUCCESS;
//            else
//              rflags.Clear(trace_bit);
//      }
//
//      rflags_scalar = rflags.GetAllFlagBits();
//      // If the code makes it here we have changes to the GPRs which
//      // we need to write back out, so lets do that.
//        if (reg_ctx->WriteRegisterValue(m_flags_reg, rflags_scalar))
//          return KERN_SUCCESS;
//    }
//  // Return the error code for reading the GPR registers back
//    return KERN_INVALID_ARGUMENT;
//}
//

//----------------------------------------------------------------------
// Register information defintions for 32 bit PowerPC.
//----------------------------------------------------------------------



RegisterContext *
MachThreadContext_x86_64::CreateRegisterContext (StackFrame *frame) const
{
    return new RegisterContextMach_x86_64(m_thread, frame);
}


//bool
//MachThreadContext_x86_64::RegisterSetStateIsValid (uint32_t set) const
//{
//    return m_state.RegisterSetIsCached(set);
//}


size_t
MachThreadContext_x86_64::GetStackFrameData(StackFrame *first_frame, std::vector<std::pair<lldb::addr_t, lldb::addr_t> >& fp_pc_pairs)
{
    fp_pc_pairs.clear();

    std::pair<lldb::addr_t, lldb::addr_t> fp_pc_pair;

    struct Frame_x86_64
    {
        uint64_t fp;
        uint64_t pc;
    };

    RegisterContext *reg_ctx = m_thread.GetRegisterContext();
    assert (reg_ctx);

    Frame_x86_64 frame = { reg_ctx->GetFP(0), reg_ctx->GetPC(LLDB_INVALID_ADDRESS) };

    fp_pc_pairs.push_back(std::make_pair(frame.fp, frame.pc));
    Error error;
    const size_t k_frame_size = sizeof(frame);
    while (frame.fp != 0 && frame.pc != 0 && ((frame.fp & 7) == 0))
    {
        // Read both the FP and PC (16 bytes)
        if (m_thread.GetProcess().ReadMemory (frame.fp, &frame.fp, k_frame_size, error) != k_frame_size)
            break;

        if (frame.pc >= 0x1000)
            fp_pc_pairs.push_back(std::make_pair(frame.fp, frame.pc));
    }
    if (!fp_pc_pairs.empty())
    {
        lldb::addr_t first_frame_pc = fp_pc_pairs.front().second;
        if (first_frame_pc != LLDB_INVALID_ADDRESS)
        {
            const uint32_t resolve_scope = eSymbolContextModule |
                                           eSymbolContextCompUnit |
                                           eSymbolContextFunction |
                                           eSymbolContextSymbol;

            SymbolContext first_frame_sc(first_frame->GetSymbolContext(resolve_scope));
            const AddressRange *addr_range_ptr = NULL;
            if (first_frame_sc.function)
                addr_range_ptr = &first_frame_sc.function->GetAddressRange();
            else if (first_frame_sc.symbol)
                addr_range_ptr = first_frame_sc.symbol->GetAddressRangePtr();

            if (addr_range_ptr)
            {
                if (first_frame->GetPC() == addr_range_ptr->GetBaseAddress())
                {
                    // We are at the first instruction, so we can recover the
                    // previous PC by dereferencing the SP
                    lldb::addr_t first_frame_sp = reg_ctx->GetSP(0);
                    // Read the real second frame return address into frame.pc
                    if (m_thread.GetProcess().ReadMemory (first_frame_sp, &frame.pc, sizeof(frame.pc), error) == sizeof(frame.pc))
                    {
                        // Construct a correct second frame (we already read the pc for it above
                        frame.fp = fp_pc_pairs.front().first;

                        // Insert the frame
                        fp_pc_pairs.insert(fp_pc_pairs.begin()+1, std::make_pair(frame.fp, frame.pc));

                        // Correct the fp in the first frame to use the SP
                        fp_pc_pairs.front().first = first_frame_sp;
                    }
                }
            }
        }
    }
    return fp_pc_pairs.size();
}


#endif    // #if defined (__i386__) || defined (__x86_64__)
