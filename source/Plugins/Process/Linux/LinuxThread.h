//===-- LinuxThread.h -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_LinuxThread_H_
#define liblldb_LinuxThread_H_

#include <memory>

#include "lldb/Target/Thread.h"

class ProcessMonitor;

//------------------------------------------------------------------------------
// @class LinuxThread
// @brief Abstraction of a linux process (thread).
class LinuxThread
    : public lldb_private::Thread
{
public:
    LinuxThread(lldb_private::Process &process, lldb::tid_t tid);

    void
    RefreshStateAfterStop();

    const char *
    GetInfo();

    uint32_t
    GetStackFrameCount();

    lldb::StackFrameSP
    GetStackFrameAtIndex(uint32_t idx);

    lldb_private::RegisterContext *
    GetRegisterContext();

    bool
    SaveFrameZeroState(RegisterCheckpoint &checkpoint);

    bool
    RestoreSaveFrameZero(const RegisterCheckpoint &checkpoint);

    lldb_private::RegisterContext *
    CreateRegisterContextForFrame(lldb_private::StackFrame *frame);

    bool
    GetRawStopReason(StopInfo *stop_info);

    //--------------------------------------------------------------------------
    // These methods form a specialized interface to linux threads.
    //
    // FIXME:  Methinks some of these should be in the generic API.
    bool Resume();


    void BreakNotify(lldb::break_id_t id);
    void TraceNotify();
    void ExitNotify();

private:
    std::auto_ptr<lldb_private::StackFrame> m_frame_ap;
    std::auto_ptr<lldb_private::RegisterContext> m_register_ap;

    lldb::break_id_t m_break_id;

    enum Notification {
        eNone,
        eBreak,
        eTrace,
        eExit
    };

    Notification m_note;

    ProcessMonitor &GetMonitor();
};

#endif // #ifndef liblldb_LinuxThread_H_
