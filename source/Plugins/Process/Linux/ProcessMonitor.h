//===-- ProcessMonitor.h -------------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ProcessMonitor_H_
#define liblldb_ProcessMonitor_H_

#include "lldb/lldb-types.h"
#include "lldb/Host/Mutex.h"

namespace lldb_private
{
class Error;
class Module;
class Scalar;
} // End lldb_private namespace.

class ProcessLinux;
class Operation;

class ProcessMonitor
{
public:

    ProcessMonitor(ProcessLinux *process,
                   lldb_private::Module *module,
                   char const *argv[],
                   char const *envp[],
                   const char *stdin_path,
                   const char *stdout_path,
                   const char *stderr_path,
                   lldb_private::Error &error);

    ~ProcessMonitor();

    lldb::pid_t
    GetPID() const { return m_pid; }

    ProcessLinux &
    GetProcess() { return *m_process; }

    int
    GetTerminalFD() const { return m_terminal_fd; }

    size_t
    ReadMemory(lldb::addr_t vm_addr, void *buf, size_t size,
               lldb_private::Error &error);

    size_t
    WriteMemory(lldb::addr_t vm_addr, const void *buf, size_t size,
                lldb_private::Error &error);

    bool
    ReadRegisterValue(unsigned offset, lldb_private::Scalar &value);

    bool
    WriteRegisterValue(unsigned offset, const lldb_private::Scalar &value);

    bool
    Resume();

    bool
    SingleStep(lldb::tid_t pid);

private:
    ProcessLinux *m_process;

    lldb::thread_t m_thread;
    lldb::pid_t m_pid;
    int m_terminal_fd;

    lldb_private::Mutex m_server_mutex;
    int m_client_fd;
    int m_server_fd;

    struct MonitorArgs
    {
        ProcessMonitor *monitor;
        lldb_private::Module *module;
        char const **argv;
        char const **envp;
        const char *stdin_path;
        const char *stdout_path;
        const char *stderr_path;
    };

    void
    StartMonitor(MonitorArgs *args, lldb_private::Error &error);

    void
    StopMonitor();

    static void *
    MonitorThread(void *arg);

    static bool
    Launch(MonitorArgs *args);

    static bool
    EnableIPC(ProcessMonitor *monitor);

    static void
    Serve(ProcessMonitor *monitor);

    static bool
    ServeSIGCHLD(ProcessMonitor *monitor, lldb::pid_t pid, int status);

    static void
    ServeOp(ProcessMonitor *monitor);

    static bool
    DupDescriptor(const char *path, int fd, int flags);

    void
    DoOperation(Operation *op);

};

#endif // #ifndef liblldb_ProcessMonitor_H_
