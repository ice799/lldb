//===-- LinuxThread.cpp -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <errno.h>

#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

#include "LinuxThread.h"
#include "ProcessLinux.h"
#include "ProcessMonitor.h"
#include "RegisterContextLinux_x86_64.h"

using namespace lldb_private;

LinuxThread::LinuxThread(Process &process, lldb::tid_t tid)
    : Thread(process, tid),
      m_frame_ap(0),
      m_register_ap(0),
      m_break_id(LLDB_INVALID_BREAK_ID),
      m_note(eNone)
{
    ArchSpec arch = process.GetTarget().GetArchitecture();

    switch (arch.GetGenericCPUType()) {
    default:
        assert(false && "CPU type not supported!");
        break;

    case ArchSpec::eCPU_x86_64:
        m_register_ap.reset(new RegisterContextLinux_x86_64(*this, NULL));
        break;
    }
}

ProcessMonitor &
LinuxThread::GetMonitor()
{
    ProcessLinux *process = static_cast<ProcessLinux*>(CalculateProcess());
    return process->GetMonitor();
}

void
LinuxThread::RefreshStateAfterStop()
{
}

const char *
LinuxThread::GetInfo()
{
    return NULL;
}

uint32_t
LinuxThread::GetStackFrameCount()
{
    return 0;
}

lldb::StackFrameSP
LinuxThread::GetStackFrameAtIndex(uint32_t idx)
{
    if (idx == 0)
    {
        RegisterContext *regs = GetRegisterContext();
        StackFrame *frame = new StackFrame(
            idx, *this, regs->GetFP(), regs->GetPC());
        return lldb::StackFrameSP(frame);
    }
    else
        return lldb::StackFrameSP();
}

RegisterContext *
LinuxThread::GetRegisterContext()
{
    return m_register_ap.get();
}

bool
LinuxThread::SaveFrameZeroState(RegisterCheckpoint &checkpoint)
{
    return false;
}

bool
LinuxThread::RestoreSaveFrameZero(const RegisterCheckpoint &checkpoint)
{
    return false;
}

lldb_private::RegisterContext *
LinuxThread::CreateRegisterContextForFrame(lldb_private::StackFrame *frame)
{
    return new RegisterContextLinux_x86_64(*this, frame);
}

bool
LinuxThread::GetRawStopReason(StopInfo *stop_info)
{
    stop_info->Clear();

    switch (m_note)
    {
    default:
        stop_info->SetStopReasonToNone();
        break;

    case eBreak:
        stop_info->SetStopReasonWithBreakpointSiteID(m_break_id);
        break;

    case eTrace:
        stop_info->SetStopReasonToTrace();
    }

    return true;
}

bool
LinuxThread::Resume()
{
    ProcessMonitor &monitor = GetMonitor();
    bool result = monitor.Resume();

    if (result)
    {
        m_note = eNone;
        SetState(lldb::eStateRunning);
    }

    return result;
}

void
LinuxThread::BreakNotify(lldb::break_id_t bid)
{
    if (m_note == eBreak && m_break_id == bid)
        return;

    m_note = eBreak;
    m_break_id = bid;
}

void
LinuxThread::TraceNotify()
{
    m_note = eTrace;
}

void
LinuxThread::ExitNotify()
{
    m_note = eExit;
}
