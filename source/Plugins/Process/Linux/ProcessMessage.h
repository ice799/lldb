//===-- ProcessMessage.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ProcessMessage_H_
#define liblldb_ProcessMessage_H_

#include <cassert>

#include "lldb/lldb-defines.h"
#include "lldb/lldb-types.h"

class ProcessMessage
{
public:

    /// The type of signal this message can correspond to.
    enum Kind
    {
        eInvalidMessage,
        eExitMessage,
        eSignalMessage,
        eTraceMessage,
        eBreakpointMessage
    };

    ProcessMessage()
        : m_kind(eInvalidMessage),
          m_pid(LLDB_INVALID_PROCESS_ID),
          m_data(0) { }

    Kind GetKind() const { return m_kind; }

    lldb::pid_t GetPID() const { return m_pid; }

    static ProcessMessage Exit(lldb::pid_t pid, int status) {
        return ProcessMessage(pid, eExitMessage, status);
    }

    static ProcessMessage Signal(lldb::pid_t pid, int signum) {
        return ProcessMessage(pid, eSignalMessage, signum);
    }

    static ProcessMessage Trace(lldb::pid_t pid) {
        return ProcessMessage(pid, eTraceMessage);
    }

    static ProcessMessage Break(lldb::pid_t pid) {
        return ProcessMessage(pid, eBreakpointMessage);
    }

    int GetExitStatus() const {
        assert(GetKind() == eExitMessage);
        return m_data;
    }

    int GetSignal() const {
        assert(GetKind() == eSignalMessage);
        return m_data;
    }

    int GetStopStatus() const {
        assert(GetKind() == eSignalMessage);
        return m_data;
    }

private:
    ProcessMessage(lldb::pid_t pid, Kind kind, int data = 0)
        : m_kind(kind),
          m_pid(pid),
          m_data(data) { }

    Kind m_kind;
    lldb::pid_t m_pid;
    int m_data;
};

#endif // #ifndef liblldb_ProcessMessage_H_
