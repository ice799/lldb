//===-- SBEvent.h -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SBEvent_h_
#define LLDB_SBEvent_h_

#include <stdio.h>
#include <vector>

#include "lldb/API/SBDefines.h"

namespace lldb {

class SBBroadcaster;

class SBEvent
{
public:
    SBEvent();

    // Make an event that contains a C string.
    SBEvent (uint32_t event, const char *cstr, uint32_t cstr_len);

    ~SBEvent();

    bool
    IsValid() const;

    void
    Dump (FILE *f) const;

    const char *
    GetDataFlavor ();

    uint32_t
    GetType () const;

    lldb::SBBroadcaster
    GetBroadcaster () const;

    bool
    BroadcasterMatchesPtr (const lldb::SBBroadcaster *broadcaster);

    bool
    BroadcasterMatchesRef (const lldb::SBBroadcaster &broadcaster);

    void
    Clear();

    static const char *
    GetCStringFromEvent (const lldb::SBEvent &event);

protected:
    friend class SBListener;
    friend class SBBroadcaster;
    friend class SBDebugger;
    friend class SBProcess;

    SBEvent (lldb::EventSP &event_sp);

#ifndef SWIG

    lldb::EventSP &
    GetSP () const;

    void
    reset (lldb::EventSP &event_sp);

    void
    reset (lldb_private::Event* event);

    lldb_private::Event *
    get () const;

#endif

private:

    mutable lldb::EventSP m_event_sp;
    mutable lldb_private::Event *m_opaque;
};

} // namespace lldb

#endif  // LLDB_SBEvent_h_
