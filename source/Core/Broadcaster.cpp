//===-- Broadcaster.cpp -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/Broadcaster.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Core/Log.h"
#include "lldb/Core/Event.h"
#include "lldb/Core/StreamString.h"
#include "lldb/lldb-private-log.h"

using namespace lldb;
using namespace lldb_private;

Broadcaster::Broadcaster (const char *name) :
    m_broadcaster_name (name),
    m_broadcaster_listeners (),
    m_broadcaster_listeners_mutex (Mutex::eMutexTypeRecursive)
{
    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_OBJECT);
    if (log)
        log->Printf ("%p Broadcaster::Broadcaster(\"%s\")", this, m_broadcaster_name.AsCString());

}

Broadcaster::~Broadcaster()
{
    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_OBJECT);
    if (log)
        log->Printf ("%p Broadcaster::~Broadcaster(\"%s\")", this, m_broadcaster_name.AsCString());

    // Scope for "listeners_locker"
    {
        Mutex::Locker listeners_locker(m_broadcaster_listeners_mutex);

        // Make sure the listener forgets about this broadcaster. We do
        // this in the broadcaster in case the broadcaster object initiates
        // the removal.

        collection::iterator pos, end = m_broadcaster_listeners.end();
        for (pos = m_broadcaster_listeners.begin(); pos != end; ++pos)
            pos->first->BroadcasterWillDestruct (this);

        m_broadcaster_listeners.clear();
    }
}

const ConstString &
Broadcaster::GetBroadcasterName ()
{
    return m_broadcaster_name;
}

void
Broadcaster::AddInitialEventsToListener (Listener *listener, uint32_t requested_events)
{

}

uint32_t
Broadcaster::AddListener (Listener* listener, uint32_t event_mask)
{
    Mutex::Locker locker(m_broadcaster_listeners_mutex);
    collection::iterator pos, end = m_broadcaster_listeners.end();

    collection::iterator existing_pos = end;
    // See if we already have this listener, and if so, update its mask
    uint32_t taken_event_types = 0;
    for (pos = m_broadcaster_listeners.begin(); pos != end; ++pos)
    {
        if (pos->first == listener)
            existing_pos = pos;
    // For now don't descriminate on who gets what
    // FIXME: Implement "unique listener for this bit" mask
    //  taken_event_types |= pos->second;
    }

    // Each event bit in a Broadcaster object can only be used
    // by one listener
    uint32_t available_event_types = ~taken_event_types & event_mask;

    if (available_event_types)
    {
        // If we didn't find our listener, add it
        if (existing_pos == end)
        {
            // Grant a new listener the available event bits
            m_broadcaster_listeners.push_back(std::make_pair(listener, available_event_types));
        }
        else
        {
            // Grant the existing listener the available event bits
            existing_pos->second |= available_event_types;
        }

        // Individual broadcasters decide whether they have outstanding data when a
        // listener attaches, and insert it into the listener with this method.

        AddInitialEventsToListener (listener, available_event_types);
    }

    // Return the event bits that were granted to the listener
    return available_event_types;
}

bool
Broadcaster::EventTypeHasListeners (uint32_t event_type)
{
    Mutex::Locker locker (m_broadcaster_listeners_mutex);
    if (m_broadcaster_listeners.empty())
        return false;

    collection::iterator pos, end = m_broadcaster_listeners.end();
    for (pos = m_broadcaster_listeners.begin(); pos != end; ++pos)
    {
        if (pos->second & event_type)
            return true;
    }
    return false;
}

bool
Broadcaster::RemoveListener (Listener* listener, uint32_t event_mask)
{
    Mutex::Locker locker(m_broadcaster_listeners_mutex);
    collection::iterator pos, end = m_broadcaster_listeners.end();
    // See if we already have this listener, and if so, update its mask
    for (pos = m_broadcaster_listeners.begin(); pos != end; ++pos)
    {
        if (pos->first == listener)
        {
            // Relinquish all event bits in "event_mask"
            pos->second &= ~event_mask;
            // If all bits have been relinquished then remove this listener
            if (pos->second == 0)
                m_broadcaster_listeners.erase (pos);
            return true;
        }
    }
    return false;
}

void
Broadcaster::BroadcastEvent (EventSP &event_sp)
{
    return PrivateBroadcastEvent (event_sp, false);
}

void
Broadcaster::BroadcastEventIfUnique (EventSP &event_sp)
{
    return PrivateBroadcastEvent (event_sp, true);
}

void
Broadcaster::PrivateBroadcastEvent (EventSP &event_sp, bool unique)
{
    // Can't add a NULL event...
    if (event_sp.get() == NULL)
        return;

    // Update the broadcaster on this event
    event_sp->SetBroadcaster (this);

    const uint32_t event_type = event_sp->GetType();

    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_EVENTS);
    if (log)
    {
        StreamString event_description;
        event_sp->Dump  (&event_description);
        log->Printf ("%p Broadcaster(\"%s\")::BroadcastEvent (event_sp = {%s}, unique =%i)",
                     this,
                     m_broadcaster_name.AsCString(""),
                     event_description.GetData(),
                     unique);
    }

    Mutex::Locker event_types_locker(m_broadcaster_listeners_mutex);
    collection::iterator pos, end = m_broadcaster_listeners.end();


    // Iterate through all listener/mask pairs
    for (pos = m_broadcaster_listeners.begin(); pos != end; ++pos)
    {
        // If the listener's mask matches any bits that we just set, then
        // put the new event on its event queue.
        if (event_type & pos->second)
        {
            if (unique && pos->first->PeekAtNextEventForBroadcasterWithType (this, event_type))
                continue;
            pos->first->AddEvent (event_sp);
        }
    }
}

void
Broadcaster::BroadcastEvent (uint32_t event_type, EventData *event_data)
{
    EventSP event_sp (new Event (event_type, event_data));
    PrivateBroadcastEvent (event_sp, false);
}

void
Broadcaster::BroadcastEventIfUnique (uint32_t event_type, EventData *event_data)
{
    EventSP event_sp (new Event (event_type, event_data));
    PrivateBroadcastEvent (event_sp, true);
}

