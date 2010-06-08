//===-- SBFrame.h -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SBFrame_h_
#define LLDB_SBFrame_h_

#include <LLDB/SBDefines.h>
#include <LLDB/SBValueList.h>

namespace lldb {

class SBValue;

class SBFrame
{
public:
    SBFrame ();

   ~SBFrame();

    bool
    IsValid() const;

    uint32_t
    GetFrameID () const;

    lldb::addr_t
    GetPC () const;

    bool
    SetPC (lldb::addr_t new_pc);

    lldb::addr_t
    GetSP () const;

    lldb::addr_t
    GetFP () const;

    lldb::SBAddress
    GetPCAddress () const;

    lldb::SBSymbolContext
    GetSymbolContext (uint32_t resolve_scope) const;

    lldb::SBModule
    GetModule () const;

    lldb::SBCompileUnit
    GetCompileUnit () const;

    lldb::SBFunction
    GetFunction () const;

    lldb::SBBlock
    GetBlock () const;

    lldb::SBLineEntry
    GetLineEntry () const;

    lldb::SBThread
    GetThread () const;

    const char *
    Disassemble () const;

    void
    Clear();

#ifndef SWIG
    bool
    operator == (const lldb::SBFrame &rhs) const;

    bool
    operator != (const lldb::SBFrame &rhs) const;

#endif

    lldb::SBValueList
    GetVariables (bool arguments,
                  bool locals,
                  bool statics,
                  bool in_scope_only);

    lldb::SBValueList
    GetRegisters ();

    lldb::SBValue
    LookupVar (const char *var_name);

    lldb::SBValue
    LookupVarInScope (const char *var_name, const char *scope);

protected:
    friend class SBValue;

    lldb_private::StackFrame *
    GetLLDBObjectPtr ();

private:
    friend class SBThread;

#ifndef SWIG

    lldb_private::StackFrame *
    operator->() const;

    // Mimic shared pointer...
    lldb_private::StackFrame *
    get() const;

#endif


    SBFrame (const lldb::StackFrameSP &lldb_object_sp);

    void
    SetFrame (const lldb::StackFrameSP &lldb_object_sp);

    lldb::StackFrameSP m_lldb_object_sp;
};

} // namespace lldb

#endif  // LLDB_SBFrame_h_
