//===-- ThreadGDBRemote.cpp -------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#include "ThreadGDBRemote.h"

#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Unwind.h"
#include "lldb/Breakpoint/WatchpointLocation.h"

#include "LibUnwindRegisterContext.h"
#include "ProcessGDBRemote.h"
#include "ProcessGDBRemoteLog.h"
#include "StringExtractorGDBRemote.h"
#include "UnwindLibUnwind.h"
#include "UnwindMacOSXFrameBackchain.h"

using namespace lldb;
using namespace lldb_private;

//----------------------------------------------------------------------
// Thread Registers
//----------------------------------------------------------------------

ThreadGDBRemote::ThreadGDBRemote (ProcessGDBRemote &process, lldb::tid_t tid) :
    Thread(process, tid),
    m_stop_info_stop_id (0),
    m_stop_info (this),
    m_thread_name (),
    m_dispatch_queue_name (),
    m_thread_dispatch_qaddr (LLDB_INVALID_ADDRESS),
    m_unwinder_ap ()
{
//    ProcessGDBRemoteLog::LogIf(GDBR_LOG_THREAD | GDBR_LOG_VERBOSE, "ThreadGDBRemote::ThreadGDBRemote ( pid = %i, tid = 0x%4.4x, )", m_process.GetID(), GetID());
    ProcessGDBRemoteLog::LogIf(GDBR_LOG_THREAD, "%p: ThreadGDBRemote::ThreadGDBRemote (pid = %i, tid = 0x%4.4x)", this, m_process.GetID(), GetID());
}

ThreadGDBRemote::~ThreadGDBRemote ()
{
    ProcessGDBRemoteLog::LogIf(GDBR_LOG_THREAD, "%p: ThreadGDBRemote::~ThreadGDBRemote (pid = %i, tid = 0x%4.4x)", this, m_process.GetID(), GetID());
}


const char *
ThreadGDBRemote::GetInfo ()
{
    return NULL;
}


const char *
ThreadGDBRemote::GetName ()
{
    if (m_thread_name.empty())
        return NULL;
    return m_thread_name.c_str();
}


const char *
ThreadGDBRemote::GetQueueName ()
{
    // Always re-fetch the dispatch queue name since it can change
    if (m_thread_dispatch_qaddr != 0 || m_thread_dispatch_qaddr != LLDB_INVALID_ADDRESS)
        return GetGDBProcess().GetDispatchQueueNameForThread (m_thread_dispatch_qaddr, m_dispatch_queue_name);
    return NULL;
}

bool
ThreadGDBRemote::WillResume (StateType resume_state)
{
    // TODO: cache for next time in case we can match things up??
    ClearStackFrames();
    int signo = GetResumeSignal();
    m_stop_info.Clear();
    switch (resume_state)
    {
    case eStateSuspended:
    case eStateStopped:
        // Don't append anything for threads that should stay stopped.
        break;

    case eStateRunning:
        if (m_process.GetUnixSignals().SignalIsValid (signo))
            GetGDBProcess().m_continue_packet.Printf(";C%2.2x:%4.4x", signo, GetID());
        else
            GetGDBProcess().m_continue_packet.Printf(";c:%4.4x", GetID());
        break;

    case eStateStepping:
        if (m_process.GetUnixSignals().SignalIsValid (signo))
            GetGDBProcess().m_continue_packet.Printf(";S%2.2x:%4.4x", signo, GetID());
        else
            GetGDBProcess().m_continue_packet.Printf(";s:%4.4x", GetID());
        break;
    }
    Thread::WillResume(resume_state);
    return true;
}

void
ThreadGDBRemote::RefreshStateAfterStop()
{
    // Invalidate all registers in our register context
    GetRegisterContext()->Invalidate();
}

Unwind *
ThreadGDBRemote::GetUnwinder ()
{
    if (m_unwinder_ap.get() == NULL)
    {
        const ArchSpec target_arch (GetProcess().GetTarget().GetArchitecture ());
        if (target_arch == ArchSpec("x86_64") ||  target_arch == ArchSpec("i386"))
        {
            m_unwinder_ap.reset (new UnwindLibUnwind (*this, GetGDBProcess().GetLibUnwindAddressSpace()));
        }
        else
        {
            m_unwinder_ap.reset (new UnwindMacOSXFrameBackchain (*this));
        }
    }
    return m_unwinder_ap.get();
}

uint32_t
ThreadGDBRemote::GetStackFrameCount()
{
    Unwind *unwinder = GetUnwinder ();
    if (unwinder)
        return unwinder->GetFrameCount();
    return 0;
}

// Make sure that GetStackFrameAtIndex() does NOT call GetStackFrameCount() when
// getting the stack frame at index zero! This way GetStackFrameCount() (via
// GetStackFRameData()) can call this function to get the first frame in order
// to provide the first frame to a lower call for efficiency sake (avoid
// redundant lookups in the frame symbol context).
lldb::StackFrameSP
ThreadGDBRemote::GetStackFrameAtIndex (uint32_t idx)
{

    StackFrameSP frame_sp (m_frames.GetFrameAtIndex(idx));

    if (frame_sp.get())
        return frame_sp;

    // Don't try and fetch a frame while process is running
// FIXME: This check isn't right because IsRunning checks the Public state, but this
// is work you need to do - for instance in ShouldStop & friends - before the public 
// state has been changed.
//    if (m_process.IsRunning())
//        return frame_sp;

    // Special case the first frame (idx == 0) so that we don't need to
    // know how many stack frames there are to get it. If we need any other
    // frames, then we do need to know if "idx" is a valid index.
    if (idx == 0)
    {
        // If this is the first frame, we want to share the thread register
        // context with the stack frame at index zero.
        GetRegisterContext();
        assert (m_reg_context_sp.get());
        frame_sp.reset (new StackFrame (idx, *this, m_reg_context_sp, m_reg_context_sp->GetSP(), m_reg_context_sp->GetPC()));
    }
    else if (idx < GetStackFrameCount())
    {
        Unwind *unwinder = GetUnwinder ();
        if (unwinder)
        {
            addr_t pc, cfa;
            if (unwinder->GetFrameInfoAtIndex(idx, cfa, pc))
                frame_sp.reset (new StackFrame (idx, *this, cfa, pc));
        }
    }
    m_frames.SetFrameAtIndex(idx, frame_sp);
    return frame_sp;
}

void
ThreadGDBRemote::ClearStackFrames ()
{
    Unwind *unwinder = GetUnwinder ();
    if (unwinder)
        unwinder->Clear();
    Thread::ClearStackFrames();
}


bool
ThreadGDBRemote::ThreadIDIsValid (lldb::tid_t thread)
{
    return thread != 0;
}

void
ThreadGDBRemote::Dump(Log *log, uint32_t index)
{
}


bool
ThreadGDBRemote::ShouldStop (bool &step_more)
{
    return true;
}
RegisterContext *
ThreadGDBRemote::GetRegisterContext ()
{
    if (m_reg_context_sp.get() == NULL)
        m_reg_context_sp.reset (CreateRegisterContextForFrame (NULL));
    return m_reg_context_sp.get();
}

RegisterContext *
ThreadGDBRemote::CreateRegisterContextForFrame (StackFrame *frame)
{
    const bool read_all_registers_at_once = false;
    uint32_t frame_idx = 0;
    
    if (frame)
        frame_idx = frame->GetID();

    if (frame_idx == 0)
        return new GDBRemoteRegisterContext (*this, frame, GetGDBProcess().m_register_info, read_all_registers_at_once);
    else if (m_unwinder_ap.get() && frame_idx < m_unwinder_ap->GetFrameCount())
        return m_unwinder_ap->CreateRegisterContextForFrame (frame);
    return NULL;
}

bool
ThreadGDBRemote::SaveFrameZeroState (RegisterCheckpoint &checkpoint)
{
    lldb::StackFrameSP frame_sp(GetStackFrameAtIndex (0));
    if (frame_sp)
    {
        checkpoint.SetStackID(frame_sp->GetStackID());
        return frame_sp->GetRegisterContext()->ReadAllRegisterValues (checkpoint.GetData());
    }
    return false;
}

bool
ThreadGDBRemote::RestoreSaveFrameZero (const RegisterCheckpoint &checkpoint)
{
    lldb::StackFrameSP frame_sp(GetStackFrameAtIndex (0));
    if (frame_sp)
    {
        bool ret = frame_sp->GetRegisterContext()->WriteAllRegisterValues (checkpoint.GetData());
        frame_sp->GetRegisterContext()->Invalidate();
        ClearStackFrames();
        return ret;
    }
    return false;
}

bool
ThreadGDBRemote::GetRawStopReason (StopInfo *stop_info)
{
    if (m_stop_info_stop_id != m_process.GetStopID())
    {
        char packet[256];
        const int packet_len = snprintf(packet, sizeof(packet), "qThreadStopInfo%x", GetID());
        assert (packet_len < (sizeof(packet) - 1));
        StringExtractorGDBRemote stop_packet;
        if (GetGDBProcess().GetGDBRemote().SendPacketAndWaitForResponse(packet, stop_packet, 1, false))
        {
            std::string copy(stop_packet.GetStringRef());
            GetGDBProcess().SetThreadStopInfo (stop_packet);
            // The process should have set the stop info stop ID and also
            // filled this thread in with valid stop info
            if (m_stop_info_stop_id != m_process.GetStopID())
            {
                //ProcessGDBRemoteLog::LogIf(GDBR_LOG_THREAD, "warning: qThreadStopInfo problem: '%s' => '%s'", packet, stop_packet.GetStringRef().c_str());
                printf("warning: qThreadStopInfo problem: '%s' => '%s'\n\torig '%s'\n", packet, stop_packet.GetStringRef().c_str(), copy.c_str()); /// REMOVE THIS
                return false;
            }
        }
    }
    *stop_info = m_stop_info;
    return true;
}


