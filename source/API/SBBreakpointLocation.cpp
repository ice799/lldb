//===-- SBBreakpointLocation.cpp --------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/API/SBBreakpointLocation.h"
#include "lldb/API/SBDefines.h"
#include "lldb/API/SBDebugger.h"

#include "lldb/lldb-types.h"
#include "lldb/lldb-defines.h"
#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Target/ThreadSpec.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Target/ThreadSpec.h"

using namespace lldb;
using namespace lldb_private;



//class SBBreakpointLocation

SBBreakpointLocation::SBBreakpointLocation ()
{
}

SBBreakpointLocation::SBBreakpointLocation (const lldb::BreakpointLocationSP &break_loc_sp) :
    m_break_loc_sp (break_loc_sp)
{
}

SBBreakpointLocation::~SBBreakpointLocation ()
{
}

bool
SBBreakpointLocation::IsValid() const
{
    return m_break_loc_sp.get() != NULL;
}

addr_t
SBBreakpointLocation::GetLoadAddress ()
{
    addr_t ret_addr = LLDB_INVALID_ADDRESS;

    if (m_break_loc_sp)
    {
        ret_addr = m_break_loc_sp->GetLoadAddress();
    }

    return ret_addr;
}

void
SBBreakpointLocation::SetEnabled (bool enabled)
{
    if (m_break_loc_sp)
    {
        m_break_loc_sp->SetEnabled (enabled);
    }
}

bool
SBBreakpointLocation::IsEnabled ()
{
    if (m_break_loc_sp)
        return m_break_loc_sp->IsEnabled();
    else
        return false;
}

int32_t
SBBreakpointLocation::GetIgnoreCount ()
{
    if (m_break_loc_sp)
        return m_break_loc_sp->GetIgnoreCount();
    else
        return 0;
}

void
SBBreakpointLocation::SetIgnoreCount (int32_t n)
{
    if (m_break_loc_sp)
        m_break_loc_sp->SetIgnoreCount (n);
}

void
SBBreakpointLocation::SetThreadID (tid_t thread_id)
{
    if (m_break_loc_sp)
        m_break_loc_sp->SetThreadID (thread_id);
}

tid_t
SBBreakpointLocation::GetThreadID ()
{
    tid_t sb_thread_id = (lldb::tid_t) LLDB_INVALID_THREAD_ID;
    if (m_break_loc_sp)
        sb_thread_id = m_break_loc_sp->GetLocationOptions()->GetThreadSpec()->GetTID();

    return sb_thread_id;
}

void
SBBreakpointLocation::SetThreadIndex (uint32_t index)
{
    if (m_break_loc_sp)
        m_break_loc_sp->GetLocationOptions()->GetThreadSpec()->SetIndex (index);
}

uint32_t
SBBreakpointLocation::GetThreadIndex() const
{
    if (m_break_loc_sp)
    {
        const ThreadSpec *thread_spec = m_break_loc_sp->GetOptionsNoCopy()->GetThreadSpec();
        if (thread_spec == NULL)
            return 0;
        else
            return thread_spec->GetIndex();
    }
    return 0;
}
    

void
SBBreakpointLocation::SetThreadName (const char *thread_name)
{
    if (m_break_loc_sp)
        m_break_loc_sp->GetLocationOptions()->GetThreadSpec()->SetName (thread_name);
}

const char *
SBBreakpointLocation::GetThreadName () const
{
    if (m_break_loc_sp)
    {
        const ThreadSpec *thread_spec = m_break_loc_sp->GetOptionsNoCopy()->GetThreadSpec();
        if (thread_spec == NULL)
            return NULL;
        else
            return thread_spec->GetName();
    }
    return NULL;
}

void
SBBreakpointLocation::SetQueueName (const char *queue_name)
{
    if (m_break_loc_sp)
        m_break_loc_sp->GetLocationOptions()->GetThreadSpec()->SetQueueName (queue_name);
}

const char *
SBBreakpointLocation::GetQueueName () const
{
    if (m_break_loc_sp)
    {
        const ThreadSpec *thread_spec = m_break_loc_sp->GetOptionsNoCopy()->GetThreadSpec();
        if (thread_spec == NULL)
            return NULL;
        else
            return thread_spec->GetQueueName();
    }
    return NULL;
}

bool
SBBreakpointLocation::IsResolved ()
{
    if (m_break_loc_sp)
        return m_break_loc_sp->IsResolved();
    else
        return false;
}

void
SBBreakpointLocation::SetLocation (const lldb::BreakpointLocationSP &break_loc_sp)
{
    if (m_break_loc_sp)
    {
        // Uninstall the callbacks?
    }
    m_break_loc_sp = break_loc_sp;
}

void
SBBreakpointLocation::GetDescription (FILE *f, const char *description_level)
{
    if (f == NULL)
        return;

    if (m_break_loc_sp)
    {
        DescriptionLevel level;
        if (strcmp (description_level, "brief") == 0)
            level = eDescriptionLevelBrief;
        else if (strcmp (description_level, "full") == 0)
            level = eDescriptionLevelFull;
        else if (strcmp (description_level, "verbose") == 0)
            level = eDescriptionLevelVerbose;
        else
            level = eDescriptionLevelBrief;

        StreamFile str (f);

        m_break_loc_sp->GetDescription (&str, level);
        str.EOL();
    }
}

SBBreakpoint
SBBreakpointLocation::GetBreakpoint ()
{
    SBBreakpoint sb_bp;
    if (m_break_loc_sp)
        *sb_bp = m_break_loc_sp->GetBreakpoint ().GetSP();    
    return sb_bp;
}

