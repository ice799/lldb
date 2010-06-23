//===-- SBListener.cpp ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/Listener.h"
#include "lldb/lldb-forward-rtti.h"
#include "lldb/Host/TimeValue.h"

#include "lldb/API/SBListener.h"
#include "lldb/API/SBEvent.h"
#include "lldb/API/SBBroadcaster.h"

using namespace lldb;
using namespace lldb_private;


SBListener::SBListener () :
    m_opaque_ptr (NULL),
    m_opaque_ptr_owned (false)
{
}

SBListener::SBListener (const char *name) :
    m_opaque_ptr (new Listener (name)),
    m_opaque_ptr_owned (true)
{
}

SBListener::SBListener (Listener &listener) :
    m_opaque_ptr (&listener),
    m_opaque_ptr_owned (false)
{
}

SBListener::~SBListener ()
{
    if (m_opaque_ptr_owned)
    {
        if (m_opaque_ptr)
        {
            delete m_opaque_ptr;
            m_opaque_ptr = NULL;
        }
    }
}

bool
SBListener::IsValid() const
{
    return m_opaque_ptr != NULL;
}

void
SBListener::AddEvent (const SBEvent &event)
{
    EventSP &event_sp = event.GetSP ();
    if (event_sp)
        m_opaque_ptr->AddEvent (event_sp);
}

void
SBListener::Clear ()
{
    if (m_opaque_ptr)
        m_opaque_ptr->Clear ();
}

uint32_t
SBListener::StartListeningForEvents (const SBBroadcaster& broadcaster, uint32_t event_mask)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        return m_opaque_ptr->StartListeningForEvents (broadcaster.get(), event_mask);
    }
    return false;
}

bool
SBListener::StopListeningForEvents (const SBBroadcaster& broadcaster, uint32_t event_mask)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        return m_opaque_ptr->StopListeningForEvents (broadcaster.get(), event_mask);
    }
    return false;
}

bool
SBListener::WaitForEvent (uint32_t num_seconds, SBEvent &event)
{
    if (m_opaque_ptr)
    {
        TimeValue time_value;
        if (num_seconds != UINT32_MAX)
        {
            assert (num_seconds != 0); // Take this out after all calls with timeout set to zero have been removed....
            time_value = TimeValue::Now();
            time_value.OffsetWithSeconds (num_seconds);
        }
        EventSP event_sp;
        if (m_opaque_ptr->WaitForEvent (time_value.IsValid() ? &time_value : NULL, event_sp))
        {
            event.reset (event_sp);
            return true;
        }
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::WaitForEventForBroadcaster
(
    uint32_t num_seconds,
    const SBBroadcaster &broadcaster,
    SBEvent &event
)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        TimeValue time_value;
        if (num_seconds != UINT32_MAX)
        {
            time_value = TimeValue::Now();
            time_value.OffsetWithSeconds (num_seconds);
        }
        EventSP event_sp;
        if (m_opaque_ptr->WaitForEventForBroadcaster (time_value.IsValid() ? &time_value : NULL,
                                                         broadcaster.get(),
                                                         event_sp))
        {
            event.reset (event_sp);
            return true;
        }

    }
    event.reset (NULL);
    return false;
}

bool
SBListener::WaitForEventForBroadcasterWithType
(
    uint32_t num_seconds,
    const SBBroadcaster &broadcaster,
    uint32_t event_type_mask,
    SBEvent &event
)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        TimeValue time_value;
        if (num_seconds != UINT32_MAX)
        {
            time_value = TimeValue::Now();
            time_value.OffsetWithSeconds (num_seconds);
        }
        EventSP event_sp;
        if (m_opaque_ptr->WaitForEventForBroadcasterWithType (time_value.IsValid() ? &time_value : NULL,
                                                              broadcaster.get(),
                                                              event_type_mask,
                                                              event_sp))
        {
            event.reset (event_sp);
            return true;
        }
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::PeekAtNextEvent (SBEvent &event)
{
    if (m_opaque_ptr)
    {
        event.reset (m_opaque_ptr->PeekAtNextEvent ());
        return event.IsValid();
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::PeekAtNextEventForBroadcaster (const SBBroadcaster &broadcaster, SBEvent &event)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        event.reset (m_opaque_ptr->PeekAtNextEventForBroadcaster (broadcaster.get()));
        return event.IsValid();
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::PeekAtNextEventForBroadcasterWithType (const SBBroadcaster &broadcaster, uint32_t event_type_mask,
                                                   SBEvent &event)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        event.reset(m_opaque_ptr->PeekAtNextEventForBroadcasterWithType (broadcaster.get(), event_type_mask));
        return event.IsValid();
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::GetNextEvent (SBEvent &event)
{
    if (m_opaque_ptr)
    {
        EventSP event_sp;
        if (m_opaque_ptr->GetNextEvent (event_sp))
        {
            event.reset (event_sp);
            return true;
        }
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::GetNextEventForBroadcaster (const SBBroadcaster &broadcaster, SBEvent &event)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        EventSP event_sp;
        if (m_opaque_ptr->GetNextEventForBroadcaster (broadcaster.get(), event_sp))
        {
            event.reset (event_sp);
            return true;
        }
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::GetNextEventForBroadcasterWithType
(
    const SBBroadcaster &broadcaster,
    uint32_t event_type_mask,
    SBEvent &event
)
{
    if (m_opaque_ptr && broadcaster.IsValid())
    {
        EventSP event_sp;
        if (m_opaque_ptr->GetNextEventForBroadcasterWithType (broadcaster.get(),
                                                              event_type_mask,
                                                              event_sp))
        {
            event.reset (event_sp);
            return true;
        }
    }
    event.reset (NULL);
    return false;
}

bool
SBListener::HandleBroadcastEvent (const SBEvent &event)
{
    if (m_opaque_ptr)
        return m_opaque_ptr->HandleBroadcastEvent (event.GetSP());
    return false;
}

Listener *
SBListener::operator->() const
{
    return m_opaque_ptr;
}

Listener *
SBListener::get() const
{
    return m_opaque_ptr;
}

void
SBListener::reset(Listener *listener, bool transfer_ownership)
{
    if (m_opaque_ptr_owned && m_opaque_ptr)
        delete m_opaque_ptr;
    m_opaque_ptr_owned = transfer_ownership;
    m_opaque_ptr = listener;
}


Listener &
SBListener::operator *()
{
    return *m_opaque_ptr;
}

const Listener &
SBListener::operator *() const
{
    return *m_opaque_ptr;
}


