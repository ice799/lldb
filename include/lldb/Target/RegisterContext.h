//===-- RegisterContext.h ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_RegisterContext_h_
#define liblldb_RegisterContext_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private.h"
#include "lldb/Target/ExecutionContextScope.h"

namespace lldb_private {

class RegisterContext :
    public ExecutionContextScope
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    RegisterContext (Thread &thread, StackFrame *frame);

    virtual
    ~RegisterContext ();

    //------------------------------------------------------------------
    // Subclasses must override these functions
    //------------------------------------------------------------------
    virtual void
    Invalidate () = 0;

    virtual size_t
    GetRegisterCount () = 0;

    virtual const lldb::RegisterInfo *
    GetRegisterInfoAtIndex (uint32_t reg) = 0;

    virtual size_t
    GetRegisterSetCount () = 0;

    virtual const lldb::RegisterSet *
    GetRegisterSet (uint32_t reg_set) = 0;

    virtual bool
    ReadRegisterValue (uint32_t reg, Scalar &value) = 0;

    virtual bool
    ReadRegisterBytes (uint32_t reg, DataExtractor &data) = 0;

    virtual bool
    ReadAllRegisterValues (lldb::DataBufferSP &data_sp) = 0;

    virtual bool
    WriteRegisterValue (uint32_t reg, const Scalar &value) = 0;

    virtual bool
    WriteRegisterBytes (uint32_t reg, DataExtractor &data, uint32_t data_offset = 0) = 0;

    virtual bool
    WriteAllRegisterValues (const lldb::DataBufferSP &data_sp) = 0;

    virtual uint32_t
    ConvertRegisterKindToRegisterNumber (uint32_t kind, uint32_t num) = 0;

    //------------------------------------------------------------------
    // Subclasses can override these functions if desired
    //------------------------------------------------------------------
    virtual uint32_t
    NumSupportedHardwareBreakpoints ();

    virtual uint32_t
    SetHardwareBreakpoint (lldb::addr_t addr, size_t size);

    virtual bool
    ClearHardwareBreakpoint (uint32_t hw_idx);

    virtual uint32_t
    NumSupportedHardwareWatchpoints ();

    virtual uint32_t
    SetHardwareWatchpoint (lldb::addr_t addr, size_t size, bool read, bool write);

    virtual bool
    ClearHardwareWatchpoint (uint32_t hw_index);

    virtual bool
    HardwareSingleStep (bool enable);

    //------------------------------------------------------------------
    // Subclasses should not override these
    //------------------------------------------------------------------
    lldb::tid_t
    GetThreadID() const;

    const lldb::RegisterInfo *
    GetRegisterInfoByName (const char *reg_name, uint32_t start_idx = 0);

    uint64_t
    GetPC (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    bool
    SetPC (uint64_t pc);

    uint64_t
    GetSP (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    bool
    SetSP (uint64_t sp);

    uint64_t
    GetFP (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    bool
    SetFP (uint64_t fp);

    const char *
    GetRegisterName (uint32_t reg);

    uint64_t
    GetReturnAddress (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    uint64_t
    GetFlags (uint64_t fail_value = 0);

    uint64_t
    ReadRegisterAsUnsigned (uint32_t reg, uint64_t fail_value);

    bool
    WriteRegisterFromUnsigned (uint32_t reg, uint64_t uval);

    //------------------------------------------------------------------
    // lldb::ExecutionContextScope pure virtual functions
    //------------------------------------------------------------------
    virtual Target *
    CalculateTarget ();

    virtual Process *
    CalculateProcess ();

    virtual Thread *
    CalculateThread ();

    virtual StackFrame *
    CalculateStackFrame ();

    virtual void
    Calculate (ExecutionContext &exe_ctx);

protected:
    //------------------------------------------------------------------
    // Classes that inherit from RegisterContext can see and modify these
    //------------------------------------------------------------------
    Thread &m_thread;       // The thread that this register context belongs to.
    StackFrame *m_frame;    // The stack frame for this context, or NULL if this is the root context
private:
    //------------------------------------------------------------------
    // For RegisterContext only
    //------------------------------------------------------------------
    DISALLOW_COPY_AND_ASSIGN (RegisterContext);
};

} // namespace lldb_private

#endif  // liblldb_RegisterContext_h_
