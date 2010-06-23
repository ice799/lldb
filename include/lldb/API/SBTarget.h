//===-- SBTarget.h ----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SBTarget_h_
#define LLDB_SBTarget_h_

#include "lldb/API/SBDefines.h"
#include "lldb/API/SBBroadcaster.h"
#include "lldb/API/SBFileSpec.h"

namespace lldb {

class SBBreakpoint;

class SBTarget
{
public:
    //------------------------------------------------------------------
    // Broadcaster bits.
    //------------------------------------------------------------------
    enum
    {
        eBroadcastBitBreakpointChanged  = (1 << 0),
        eBroadcastBitModulesLoaded      = (1 << 1),
        eBroadcastBitModulesUnloaded    = (1 << 2)
    };

    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    SBTarget (const lldb::SBTarget& rhs);

    SBTarget ();  // Required for SWIG.

    //------------------------------------------------------------------
    // Destructor
    //------------------------------------------------------------------
    ~SBTarget();

    const lldb::SBTarget&
    Assign (const lldb::SBTarget& rhs);

    bool
    IsValid() const;

    lldb::SBProcess
    GetProcess ();

    lldb::SBProcess
    CreateProcess ();

    lldb::SBProcess
    LaunchProcess (char const **argv,
                   char const **envp,
                   const char *tty,
                   bool stop_at_entry);

    lldb::SBFileSpec
    GetExecutable ();

    uint32_t
    GetNumModules () const;

    lldb::SBModule
    GetModuleAtIndex (uint32_t idx);

    lldb::SBDebugger
    GetDebugger() const;

    lldb::SBModule
    FindModule (const lldb::SBFileSpec &file_spec);

    bool
    DeleteTargetFromList (lldb_private::TargetList *list);

    bool
    MakeCurrentTarget ();

    lldb::SBBreakpoint
    BreakpointCreateByLocation (const char *file, uint32_t line);

    lldb::SBBreakpoint
    BreakpointCreateByLocation (const lldb::SBFileSpec &file_spec, uint32_t line);

    lldb::SBBreakpoint
    BreakpointCreateByName (const char *symbol_name, const char *module_name = NULL);

    lldb::SBBreakpoint
    BreakpointCreateByRegex (const char *symbol_name_regex, const char *module_name = NULL);

    lldb::SBBreakpoint
    BreakpointCreateByAddress (addr_t address);

    bool
    BreakpointDelete (break_id_t break_id);

    void
    ListAllBreakpoints ();

    lldb::SBBreakpoint
    FindBreakpointByID (break_id_t break_id);

    bool
    EnableAllBreakpoints ();

    bool
    DisableAllBreakpoints ();

    bool
    DeleteAllBreakpoints ();

    lldb::SBBroadcaster
    GetBroadcaster () const;

    //void
    //Disassemble ();

    void
    Disassemble (lldb::addr_t file_address_start, lldb::addr_t file_address_end = LLDB_INVALID_ADDRESS,
                 const char *module_name = NULL);

    void
    Disassemble (const char *function_name, const char *module_name = NULL);

#ifndef SWIG
    bool
    operator == (const lldb::SBTarget &rhs) const;

    bool
    operator != (const lldb::SBTarget &rhs) const;

#endif

protected:
    friend class SBDebugger;
    friend class SBProcess;

    //------------------------------------------------------------------
    // Constructors are private, use static Target::Create function to
    // create an instance of this class.
    //------------------------------------------------------------------

    SBTarget (const lldb::TargetSP& target_sp);

    void
    reset (const lldb::TargetSP& target_sp);

    lldb_private::Target *
    operator ->() const;

    lldb_private::Target *
    get() const;

private:
    //------------------------------------------------------------------
    // For Target only
    //------------------------------------------------------------------

    lldb::TargetSP m_opaque_sp;
};

} // namespace lldb

#endif  // LLDB_SBTarget_h_
