//===-- SBBroadcaster.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SBBroadcaster_h_
#define LLDB_SBBroadcaster_h_

#include "lldb/API/SBDefines.h"

namespace lldb {

class SBBroadcaster
{
public:
    SBBroadcaster ();

    SBBroadcaster (const char *name);

    ~SBBroadcaster();

    bool
    IsValid () const;

    void
    BroadcastEventByType (uint32_t event_type, bool unique = false);

    void
    BroadcastEvent (const lldb::SBEvent &event, bool unique = false);

    void
    AddInitialEventsToListener (const lldb::SBListener &listener, uint32_t requested_events);

    uint32_t
    AddListener (const lldb::SBListener &listener, uint32_t event_mask);

    const char *
    GetName ();

    bool
    EventTypeHasListeners (uint32_t event_type);

    bool
    RemoveListener (const lldb::SBListener &listener, uint32_t event_mask = UINT32_MAX);

#ifndef SWIG
    bool
    operator == (const lldb::SBBroadcaster &rhs) const;

    bool
    operator != (const lldb::SBBroadcaster &rhs) const;

#endif

protected:
    friend class SBCommandInterpreter;
    friend class SBCommunication;
    friend class SBEvent;
    friend class SBListener;
    friend class SBProcess;
    friend class SBTarget;

    SBBroadcaster (lldb_private::Broadcaster *broadcaster, bool owns);

#ifndef SWIG

    lldb_private::Broadcaster *
    get () const;

    void
    reset (lldb_private::Broadcaster *broadcaster, bool owns);

#endif

private:

    lldb_private::Broadcaster *m_opaque;
    bool m_opaque_owned;
};

} // namespace lldb

#endif  // LLDB_SBBroadcaster_h_
