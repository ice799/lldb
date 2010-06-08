//===-- BreakpointLocation.cpp ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
// C++ Includes
#include <string>

// Other libraries and framework includes
// Project includes
#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Breakpoint/BreakpointID.h"
#include "lldb/Breakpoint/StoppointCallbackContext.h"
#include "lldb/Core/Log.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Process.h"
#include "lldb/Core/StreamString.h"
#include "lldb/lldb-private-log.h"
#include "lldb/Target/Thread.h"

using namespace lldb;
using namespace lldb_private;

BreakpointLocation::BreakpointLocation
(
    break_id_t loc_id,
    Breakpoint &owner,
    Address &addr,
    lldb::tid_t tid,
    bool hardware
) :
    StoppointLocation (loc_id, addr.GetLoadAddress(owner.GetTarget().GetProcessSP().get()), tid, hardware),
    m_address (addr),
    m_owner (owner),
    m_options_ap (),
    m_bp_site_sp ()
{
}

BreakpointLocation::~BreakpointLocation()
{
    ClearBreakpointSite();
}

lldb::addr_t
BreakpointLocation::GetLoadAddress ()
{
    return m_address.GetLoadAddress(m_owner.GetTarget().GetProcessSP().get());
}

Address &
BreakpointLocation::GetAddress ()
{
    return m_address;
}

Breakpoint &
BreakpointLocation::GetBreakpoint ()
{
    return m_owner;
}

bool
BreakpointLocation::IsEnabled ()
{
    if (!m_owner.IsEnabled())
        return false;
    else if (m_options_ap.get() != NULL)
        return m_options_ap->IsEnabled();
    else
        return true;
}

void
BreakpointLocation::SetEnabled (bool enabled)
{
    GetLocationOptions()->SetEnabled(enabled);
    if (enabled)
    {
        ResolveBreakpointSite();
    }
    else
    {
        ClearBreakpointSite();
    }
}

void
BreakpointLocation::SetThreadID (lldb::tid_t thread_id)
{
    GetLocationOptions()->SetThreadID(thread_id);
}

lldb::tid_t
BreakpointLocation::GetThreadID ()
{
    return GetOptionsNoCopy()->GetThreadID();
}

bool
BreakpointLocation::InvokeCallback (StoppointCallbackContext *context)
{
    bool owner_result;

    owner_result = m_owner.InvokeCallback (context, GetID());
    if (owner_result == false)
        return false;
    else if (m_options_ap.get() != NULL)
        return m_options_ap->InvokeCallback (context, m_owner.GetID(), GetID());
    else
        return true;
}

void
BreakpointLocation::SetCallback (BreakpointHitCallback callback, void *baton,
                 bool is_synchronous)
{
    // The default "Baton" class will keep a copy of "baton" and won't free
    // or delete it when it goes goes out of scope.
    GetLocationOptions()->SetCallback(callback, BatonSP (new Baton(baton)), is_synchronous);
}

void
BreakpointLocation::SetCallback (BreakpointHitCallback callback, const BatonSP &baton_sp,
                 bool is_synchronous)
{
    GetLocationOptions()->SetCallback (callback, baton_sp, is_synchronous);
}

void
BreakpointLocation::ClearCallback ()
{
    GetLocationOptions()->ClearCallback();
}

int32_t
BreakpointLocation::GetIgnoreCount ()
{
    return GetOptionsNoCopy()->GetIgnoreCount();
}

void
BreakpointLocation::SetIgnoreCount (int32_t n)
{
    GetLocationOptions()->SetIgnoreCount(n);
}

BreakpointOptions *
BreakpointLocation::GetOptionsNoCopy ()
{
    if (m_options_ap.get() != NULL)
        return m_options_ap.get();
    else
        return m_owner.GetOptions ();
}

BreakpointOptions *
BreakpointLocation::GetLocationOptions ()
{
    if (m_options_ap.get() == NULL)
        m_options_ap.reset(new BreakpointOptions (*m_owner.GetOptions ()));

    return m_options_ap.get();
}

// RETURNS - true if we should stop at this breakpoint, false if we
// should continue.

bool
BreakpointLocation::ShouldStop (StoppointCallbackContext *context)
{
    bool should_stop = true;

    m_hit_count++;

    if (!IsEnabled())
        return false;

    if (GetThreadID() != LLDB_INVALID_THREAD_ID
          && context->context.thread->GetID() != GetThreadID())
        return false;

    if (m_hit_count <= GetIgnoreCount())
        return false;

    // Tell if the callback is synchronous here.
    context->is_synchronous = true;
    should_stop = InvokeCallback (context);
        
    if (should_stop)
    {
        Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_BREAKPOINTS);
        if (log)
        {
            StreamString s;
            GetDescription (&s, lldb::eDescriptionLevelVerbose);
            log->Printf ("Hit breakpoint location: %s\n", s.GetData());
        }
    }
    return should_stop;
}

bool
BreakpointLocation::IsResolved () const
{
    return m_bp_site_sp.get() != NULL;
}

bool
BreakpointLocation::ResolveBreakpointSite ()
{
    if (m_bp_site_sp)
        return true;

    Process* process = m_owner.GetTarget().GetProcessSP().get();
    if (process == NULL)
        return false;

    BreakpointLocationSP myself_sp(m_owner.GetLocationSP (this));

    lldb::user_id_t new_id = process->CreateBreakpointSite (myself_sp, false);

    if (new_id == LLDB_INVALID_UID)
    {
        Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_BREAKPOINTS);
        if (log)
            log->Warning ("Tried to add breakpoint site at 0x%llx but it was already present.\n",
                          m_address.GetLoadAddress(process));
        return false;
    }

    return true;
}

bool
BreakpointLocation::SetBreakpointSite (BreakpointSiteSP& bp_site_sp)
{
    m_bp_site_sp = bp_site_sp;
    return true;
}

bool
BreakpointLocation::ClearBreakpointSite ()
{
    if (m_bp_site_sp.get())
    {
        m_owner.GetTarget().GetProcessSP()->RemoveOwnerFromBreakpointSite (GetBreakpoint().GetID(), GetID(), m_bp_site_sp);
        m_bp_site_sp.reset();
        return true;
    }
    return false;
}

void
BreakpointLocation::GetDescription (Stream *s, lldb::DescriptionLevel level)
{
    SymbolContext sc;
    s->Indent();
    BreakpointID::GetCanonicalReference(s, m_owner.GetID(), GetID());

    if (level == lldb::eDescriptionLevelBrief)
        return;

    s->PutCString(": ");

    if (level == lldb::eDescriptionLevelVerbose)
        s->IndentMore();

    if (m_address.IsSectionOffset())
    {
        m_address.CalculateSymbolContext(&sc);

        if (level == lldb::eDescriptionLevelFull)
        {
            s->PutCString("where = ");
            sc.DumpStopContext (s, m_owner.GetTarget().GetProcessSP().get(), m_address);
        }
        else
        {
            if (sc.module_sp)
            {
                s->EOL();
                s->Indent("module = ");
                sc.module_sp->GetFileSpec().Dump (s);
            }

            if (sc.comp_unit != NULL)
            {
                s->EOL();
                s->Indent("compile unit = ");
                dynamic_cast<FileSpec*>(sc.comp_unit)->GetFilename().Dump (s);

                if (sc.function != NULL)
                {
                    s->EOL();
                    s->Indent("function = ");
                    s->PutCString (sc.function->GetMangled().GetName().AsCString("<unknown>"));
                }

                if (sc.line_entry.line > 0)
                {
                    s->EOL();
                    s->Indent("location = ");
                    sc.line_entry.DumpStopContext (s);
                }

            }
            else
            {
                // If we don't have a comp unit, see if we have a symbol we can print.
                if (sc.symbol)
                {
                    s->EOL();
                    s->Indent("symbol = ");
                    s->PutCString(sc.symbol->GetMangled().GetName().AsCString("<unknown>"));
                }
            }
        }
    }

    if (level == lldb::eDescriptionLevelVerbose)
    {
        s->EOL();
        s->Indent();
    }
    s->Printf ("%saddress = ", (level == lldb::eDescriptionLevelFull && m_address.IsSectionOffset()) ? ", " : "");
    ExecutionContextScope *exe_scope = NULL;
    Target *target = &m_owner.GetTarget();
    if (target)
        exe_scope = target->GetProcessSP().get();
    if (exe_scope == NULL)
        exe_scope = target;

    m_address.Dump(s, exe_scope, Address::DumpStyleLoadAddress, Address::DumpStyleModuleWithFileAddress);

    if (level == lldb::eDescriptionLevelVerbose)
    {
        s->EOL();
        s->Indent();
        s->Printf("resolved = %s\n", IsResolved() ? "true" : "false");

        s->Indent();
        s->Printf("enabled = %s\n", IsEnabled() ? "true" : "false");

        s->Indent();
        s->Printf ("hit count = %-4u\n", GetHitCount());

        if (m_options_ap.get())
        {
            Baton *baton = m_options_ap->GetBaton();
            if (baton)
            {
                s->Indent();
                baton->GetDescription (s, level);
                s->EOL();
            }
        }
        s->IndentLess();
    }
    else
    {
        s->Printf(", %sresolved, %s, hit count = %u",
                  (IsResolved() ? "" : "un"),
                  (IsEnabled() ? "enabled" : "disabled"),
                  GetHitCount());
    }
}

void
BreakpointLocation::Dump(Stream *s) const
{
    if (s == NULL)
        return;

    s->Printf("BreakpointLocation %u: tid = %4.4x  load addr = 0x%8.8llx  state = %s  type = %s breakpoint  hw_index = %i  hit_count = %-4u  ignore_count = %-4u",
            GetID(),
            m_tid,
            (uint64_t) m_address.GetLoadAddress(m_owner.GetTarget().GetProcessSP().get()),
            (m_options_ap.get() ? m_options_ap->IsEnabled() : m_owner.IsEnabled()) ? "enabled " : "disabled",
            IsHardware() ? "hardware" : "software",
            GetHardwareIndex(),
            GetHitCount(),
            m_options_ap.get() ? m_options_ap->GetIgnoreCount() : m_owner.GetIgnoreCount());
}
