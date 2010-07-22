//===-- ProcessMonitor.cpp ------------------------------------ -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lldb/Core/Error.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Host/Host.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Utility/PseudoTerminal.h"

#include "LinuxThread.h"
#include "ProcessLinux.h"
#include "ProcessMonitor.h"

using namespace lldb_private;

//------------------------------------------------------------------------------
// Static implementations of ProcessMonitor::ReadMemory and
// ProcessMonitor::WriteMemory.  This enables mutual recursion between these
// functions without needed to go thru the thread funnel.

static size_t
DoReadMemory(lldb::pid_t pid, unsigned word_size,
             lldb::addr_t vm_addr, void *buf, size_t size, Error &error)
{
    unsigned char *dst = static_cast<unsigned char*>(buf);
    size_t bytes_read;
    size_t remainder;
    long data;

    for (bytes_read = 0; bytes_read < size; bytes_read += remainder)
    {
        errno = 0;
        data = ptrace(PTRACE_PEEKDATA, pid, vm_addr, NULL);

        if (data == -1L && errno)
        {
            error.SetErrorToErrno();
            return bytes_read;
        }

        remainder = size - bytes_read;
        remainder = remainder > word_size ? word_size : remainder;
        for (unsigned i = 0; i < remainder; ++i)
            dst[i] = ((data >> i*8) & 0xFF);
        vm_addr += word_size;
        dst += word_size;
    }

    return bytes_read;
}

static size_t
DoWriteMemory(lldb::pid_t pid, unsigned word_size,
              lldb::addr_t vm_addr, const void *buf, size_t size, Error &error)
{
    const unsigned char *src = static_cast<const unsigned char*>(buf);
    size_t bytes_written = 0;
    size_t remainder;

    for (bytes_written = 0; bytes_written < size; bytes_written += remainder)
    {
        remainder = size - bytes_written;
        remainder = remainder > word_size ? word_size : remainder;

        if (remainder == word_size)
        {
            unsigned long data = 0;
            for (unsigned i = 0; i < word_size; ++i)
                data |= (unsigned long)src[i] << i*8;

            if (ptrace(PTRACE_POKEDATA, pid, vm_addr, data) == -1)
            {
                error.SetErrorToErrno();
                return bytes_written;
            }
        }
        else
        {
            unsigned char buff[8];
            if (DoReadMemory(pid, word_size, vm_addr,
                             buff, word_size, error) != word_size)
                return bytes_written;

            memcpy(buff, src, remainder);

            if (DoWriteMemory(pid, word_size, vm_addr,
                              buff, word_size, error) != word_size)
                return bytes_written;
        }

        vm_addr += word_size;
        src += word_size;
    }
    return bytes_written;
}


//------------------------------------------------------------------------------
/// @class Operation
/// @brief Represents a ProcessMonitor operation.
///
/// Under Linux, it is not possible to ptrace() from any other thread but the
/// one that spawned or attached to the process from the start.  Therefore, when
/// a ProcessMonitor is asked to deliver or change the state of an inferior
/// process the operation must be "funneled" to a specific thread to perform the
/// task.  The Operation class provides an abstract base for all services the
/// ProcessMonitor must perform via the single virtual function Execute, thus
/// encapsulating the code to be executed in the privileged context.
class Operation
{
public:
    virtual void Execute(ProcessMonitor *monitor) = 0;
};

//------------------------------------------------------------------------------
/// @class ReadOperation
/// @brief Implements ProcessMonitor::ReadMemory.
class ReadOperation : public Operation
{
public:
    ReadOperation(lldb::addr_t addr, void *buff, size_t size,
                  Error &error, size_t &result)
        : m_addr(addr), m_buff(buff), m_size(size),
          m_error(error), m_result(result)
        { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::addr_t m_addr;
    void *m_buff;
    size_t m_size;
    Error &m_error;
    size_t &m_result;
};

void
ReadOperation::Execute(ProcessMonitor *monitor)
{
    const unsigned word_size = monitor->GetProcess().GetAddressByteSize();
    lldb::pid_t pid = monitor->GetPID();

    m_result = DoReadMemory(pid, word_size, m_addr, m_buff, m_size, m_error);
}

//------------------------------------------------------------------------------
/// @class ReadOperation
/// @brief Implements ProcessMonitor::WriteMemory.
class WriteOperation : public Operation
{
public:
    WriteOperation(lldb::addr_t addr, const void *buff, size_t size,
                   Error &error, size_t &result)
        : m_addr(addr), m_buff(buff), m_size(size),
          m_error(error), m_result(result)
        { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::addr_t m_addr;
    const void *m_buff;
    size_t m_size;
    Error &m_error;
    size_t &m_result;
};

void
WriteOperation::Execute(ProcessMonitor *monitor)
{
    const unsigned word_size = monitor->GetProcess().GetAddressByteSize();
    lldb::pid_t pid = monitor->GetPID();

    m_result = DoWriteMemory(pid, word_size, m_addr, m_buff, m_size, m_error);
}

//------------------------------------------------------------------------------
/// @class ReadRegOperation
/// @brief Implements ProcessMonitor::ReadRegisterValue.
class ReadRegOperation : public Operation
{
public:
    ReadRegOperation(unsigned offset, Scalar &value, bool &result)
        : m_offset(offset), m_value(value), m_result(result)
        { }

    void Execute(ProcessMonitor *monitor);

private:
    unsigned m_offset;
    Scalar &m_value;
    bool &m_result;
};

void
ReadRegOperation::Execute(ProcessMonitor *monitor)
{
    lldb::pid_t pid = monitor->GetPID();

    // Set errno to zero so that we can detect a failed peek.
    errno = 0;
    unsigned long data = ptrace(PTRACE_PEEKUSER, pid, m_offset, NULL);

    if (data == -1UL && errno)
        m_result = false;
    else
    {
        m_value = data;
        m_result = true;
    }
}

//------------------------------------------------------------------------------
/// @class WriteRegOperation
/// @brief Implements ProcessMonitor::WriteRegisterValue.
class WriteRegOperation : public Operation
{
public:
    WriteRegOperation(unsigned offset, const Scalar &value, bool &result)
        : m_offset(offset), m_value(value), m_result(result)
        { }

    void Execute(ProcessMonitor *monitor);

private:
    unsigned m_offset;
    const Scalar &m_value;
    bool &m_result;
};

void
WriteRegOperation::Execute(ProcessMonitor *monitor)
{
    lldb::pid_t pid = monitor->GetPID();

    if (ptrace(PTRACE_POKEUSER, pid, m_offset, m_value.ULong()))
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ResumeOperation
/// @brief Implements ProcessMonitor::Resume.
class ResumeOperation : public Operation
{
public:
    ResumeOperation(lldb::tid_t tid, bool &result) : 
        m_tid(tid), m_result(result) { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::tid_t m_tid;
    bool &m_result;
};

void
ResumeOperation::Execute(ProcessMonitor *monitor)
{
    if (ptrace(PTRACE_CONT, m_tid, NULL, NULL) == -1L)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ResumeOperation
/// @brief Implements ProcessMonitor::SingleStep.
class SingleStepOperation : public Operation
{
public:
    SingleStepOperation(lldb::tid_t tid, bool &result) 
        : m_tid(tid), m_result(result) { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::tid_t m_tid;
    bool &m_result;
};

void
SingleStepOperation::Execute(ProcessMonitor *monitor)
{
    if (ptrace(PTRACE_SINGLESTEP, m_tid, NULL, NULL) == -1L)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class SiginfoOperation
/// @brief Implements ProcessMonitor::GetSignalInfo.
class SiginfoOperation : public Operation
{
public:
    SiginfoOperation(lldb::tid_t tid, void *info, bool &result) 
        : m_tid(tid), m_info(info), m_result(result) { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::tid_t m_tid;
    void *m_info;
    bool &m_result;
};

void
SiginfoOperation::Execute(ProcessMonitor *monitor)
{
    if (ptrace(PTRACE_GETSIGINFO, m_tid, NULL, m_info) == -1L)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class EventMessageOperation
/// @brief Implements ProcessMonitor::GetEventMessage.
class EventMessageOperation : public Operation
{
public:
    EventMessageOperation(lldb::tid_t tid, unsigned long *message, bool &result) 
        : m_tid(tid), m_message(message), m_result(result) { }

    void Execute(ProcessMonitor *monitor);

private:
    lldb::tid_t m_tid;
    unsigned long *m_message;
    bool &m_result;
};

void
EventMessageOperation::Execute(ProcessMonitor *monitor)
{
    if (ptrace(PTRACE_GETEVENTMSG, m_tid, NULL, m_message) == -1L)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// The basic design of the ProcessMonitor is built around two threads.  
///
/// One thread (@see SignalThread) simply blocks on a call to waitpid() looking
/// for changes in the debugee state.  When a change is detected a
/// ProcessMessage is sent to the associated ProcessLinux instance.  This thread
/// "drives" state changes in the debugger.
///
/// The second thread (@see OperationThread) is responsible for two things 1)
/// lauching or attaching to the inferior process, and then 2) servicing
/// operations such as register reads/writes, stepping, etc.  See the comments
/// on the Operation class for more info as to why this is needed.
ProcessMonitor::ProcessMonitor(ProcessLinux *process,
                               Module *module,
                               const char *argv[],
                               const char *envp[],
                               const char *stdin_path,
                               const char *stdout_path,
                               const char *stderr_path,
                               lldb_private::Error &error)
    : m_process(process),
      m_operation_thread(LLDB_INVALID_HOST_THREAD),
      m_signal_thread(LLDB_INVALID_HOST_THREAD),
      m_pid(LLDB_INVALID_PROCESS_ID),
      m_terminal_fd(-1),
      m_client_fd(-1),
      m_server_fd(-1)
{
    LaunchArgs *args = new LaunchArgs();

    // FIXME: All this string copying should happen in a LaunchArgs ctor.
    unsigned argv_len = 0;
    unsigned envp_len = 0;

    for (unsigned i = 0; argv[i]; ++i)
        argv_len++;

    for (unsigned i = 0; envp[i]; ++i)
        envp_len++;

    const char **arvec = new const char*[argv_len + 1];
    const char **envec = new const char*[envp_len + 1];

    for (unsigned i = 0; i < argv_len; ++i)
        arvec[i] = strdup(argv[i]);
    arvec[argv_len] = 0;

    for (unsigned i = 0; i < envp_len; ++i)
        envec[i] = strdup(envp[i]);
    envec[envp_len] = 0;

    args->monitor = this;
    args->module = module;
    args->argv = arvec;
    args->envp = envec;
    args->stdin_path = NULL;
    args->stdout_path = NULL;
    args->stderr_path = NULL;

    // Server/client descriptors.
    if (!EnableIPC())
        error.SetErrorToGenericError();

    StartOperationThread(args, error);
}

ProcessMonitor::~ProcessMonitor()
{
    StopSignalThread();
    StopOperationThread();

    close(m_terminal_fd);
    close(m_client_fd);
    close(m_server_fd);
}

//------------------------------------------------------------------------------
// Thread setup and tear down.
void
ProcessMonitor::StartOperationThread(LaunchArgs *args, Error &error)
{
    static const char *g_thread_name = "lldb.process.linux.operation";

    if (m_operation_thread != LLDB_INVALID_HOST_THREAD)
        return;

    m_operation_thread = 
        Host::ThreadCreate(g_thread_name, OperationThread, args, &error);
}

void
ProcessMonitor::StopOperationThread()
{
    lldb::thread_result_t result;

    if (m_operation_thread == LLDB_INVALID_HOST_THREAD)
        return;

    Host::ThreadCancel(m_operation_thread, NULL);
    Host::ThreadJoin(m_operation_thread, &result, NULL);
}

bool
ProcessMonitor::StartSignalThread(ProcessMonitor *monitor)
{
    static const char *g_thread_name = "lldb.process.linux.signal";

    if (monitor->m_signal_thread != LLDB_INVALID_HOST_THREAD)
        return false;

    Error error;
    monitor->m_signal_thread =
        Host::ThreadCreate(g_thread_name, SignalThread, monitor, &error);
    return error.Success();
}

void
ProcessMonitor::StopSignalThread()
{
    lldb::thread_result_t result;

    if (m_signal_thread == LLDB_INVALID_HOST_THREAD)
        return;

    Host::ThreadCancel(m_signal_thread, NULL);
    Host::ThreadJoin(m_signal_thread, &result, NULL);
}

void *
ProcessMonitor::OperationThread(void *arg)
{
    std::auto_ptr<LaunchArgs> args(static_cast<LaunchArgs*>(arg));

    if (!Launch(args.get()))
        return NULL;

    if (!StartSignalThread(args->monitor))
        return NULL;

    ServeOperation(args->monitor);
    return NULL;
}

bool
ProcessMonitor::Launch(LaunchArgs *args)
{
    ProcessMonitor *monitor = args->monitor;
    const char **argv = args->argv;
    const char **envp = args->envp;
    const char *stdin_path = args->stdin_path;
    const char *stdout_path = args->stdout_path;
    const char *stderr_path = args->stderr_path;

    lldb_utility::PseudoTerminal terminal;
    const size_t err_len = 1024;
    char err_str[err_len];
    lldb::pid_t pid;

    // Pseudo terminal setup.
    if (!terminal.OpenFirstAvailableMaster(O_RDWR | O_NOCTTY, err_str, err_len))
        return false;

    if ((pid = terminal.Fork(err_str, err_len)) < 0)
        return false;

    // Child process.
    if (pid == 0)
    {
        // Trace this process.
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // Do not inherit setgid powers.
        setgid(getgid());

        // Let us have our own process group.
        setpgid(0, 0);

        // Dup file discriptors if needed.
        //
        // FIXME: If two or more of the paths are the same we needlessly open
        // the same file multiple times.
        if (stdin_path != NULL && stdin_path[0])
            if (!DupDescriptor(stdin_path, STDIN_FILENO, O_RDONLY | O_CREAT))
                exit(1);

        if (stdout_path != NULL && stdout_path[0])
            if (!DupDescriptor(stdout_path, STDOUT_FILENO, O_WRONLY | O_CREAT))
                exit(1);

        if (stderr_path != NULL && stderr_path[0])
            if (!DupDescriptor(stderr_path, STDOUT_FILENO, O_WRONLY | O_CREAT))
                exit(1);

        // Execute.  We should never return.
        execve(argv[0],
               const_cast<char *const *>(argv),
               const_cast<char *const *>(envp));
        exit(-1);
    }

    // Wait for the child process to to trap on its call to execve.
    int status;
    if ((status = waitpid(pid, &status, 0)) < 0)
        return false;           // execve likely failed for some reason.
    assert(status == pid && "Could not sync with inferrior process.");

    // Have the child raise an event on exit.  This is used to keep the child in
    // limbo until it is destroyed.
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT) < 0)
        return false;
    
    // Release the master terminal descriptor and pass it off to the
    // ProcessMonitor instance.  Similarly stash the inferior pid.
    monitor->m_terminal_fd = terminal.ReleaseMasterFileDescriptor();
    monitor->m_pid = pid;

    // Add the new thread of execution to the process instance.
    //
    // FIXME: We should implement a synchronization point between the monitor
    // thread and the context in which ProcessLinux::DoLaunch was called.  The
    // only reason this code is here is to paper over the need for syncing.
    ProcessLinux &process = monitor->GetProcess();
    lldb::ThreadSP inferior(new LinuxThread(process, pid));
    process.GetThreadList().AddThread(inferior);
    process.GetThreadList().SetCurrentThreadByID(pid);

    // Notify the process instance it has stopped.
    process.SendMessage(ProcessMessage::Trace(pid));

    return true;
}

bool
ProcessMonitor::EnableIPC()
{
    int fd[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        return false;

    m_client_fd = fd[0];
    m_server_fd = fd[1];
    return true;
}

void *
ProcessMonitor::SignalThread(void *arg)
{
    ProcessMessage message;
    ProcessMonitor *monitor = static_cast<ProcessMonitor*>(arg);
    ProcessLinux *process = monitor->m_process;
    lldb::pid_t pid;
    int status;

    for (;;) 
    {
        if ((pid = waitpid(WAIT_ANY, &status, WUNTRACED)) < 0)
            return NULL;

        if (WIFEXITED(status))
        {
            message = ProcessMessage::Exit(pid, WEXITSTATUS(status));
            process->SendMessage(message);
            return NULL;
        }
        
        if (WIFSIGNALED(status))
        {
            message = ProcessMessage::Signal(pid, WTERMSIG(status));
            process->SendMessage(message);
            return NULL;
        }
        
        if (WIFSTOPPED(status))
        {
            siginfo_t info;
            if (!monitor->GetSignalInfo(pid, &info))
                return NULL;
            assert(info.si_signo == SIGTRAP && "Unexpected child signal!");
            
            switch (info.si_code)
            {
            default:
                assert(false && "Unexpected SIGTRAP code!");
                break;
                
            case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
            {
                // The inferior process is about to exit.  Maintain the process
                // in a state of "limbo" until we are explicitly commanded to
                // detatch, destroy, resume, etc.
                //
                // FIXME: Confirm this extracts the correct bits.
                unsigned long data = 0;
                if (!monitor->GetEventMessage(pid, &data))
                    data = -1;
                message = ProcessMessage::Exit(pid, (data >> 8));
                break;
            }

            case 0:
            case TRAP_TRACE:
                message = ProcessMessage::Trace(pid);
                break;
                
            case SI_KERNEL:
            case TRAP_BRKPT:
                message = ProcessMessage::Break(pid);
                break;
            }
            process->SendMessage(message);
        }
    }

    assert(false && "Unexpected child signal!");
    return NULL;
}

void
ProcessMonitor::ServeOperation(ProcessMonitor *monitor)
{
    int status;
    pollfd fdset;

    fdset.fd = monitor->m_server_fd;
    fdset.events = POLLIN | POLLPRI;
    fdset.revents = 0;

    for (;;)
    {
        if ((status = poll(&fdset, 1, -1)) < 0)
        {
            switch (errno) 
            {
            default:
                assert(false && "Unexpected poll() failure!");
                continue;

            case EINTR: continue; // Just poll again.
            case EBADF: return;   // Connection terminated.
            }
        }

        assert(status == 1 && "Too many descriptors!");

        if (fdset.revents & POLLIN) 
        {
            Operation *op = NULL;

        READ_AGAIN:
            if ((status = read(fdset.fd, &op, sizeof(op))) < 0)
            {
                // There is only one acceptable failure.
                assert(errno == EINTR);
                goto READ_AGAIN;
            }

            assert(status == sizeof(op));
            op->Execute(monitor);
            write(fdset.fd, &op, sizeof(op));
        }
    }
}

void
ProcessMonitor::DoOperation(Operation *op)
{
    int status;
    Operation *ack = NULL;
    Mutex::Locker lock(m_server_mutex);
    
    // FIXME: Do proper error checking here.
    write(m_client_fd, &op, sizeof(op));

READ_AGAIN:
    if ((status = read(m_client_fd, &ack, sizeof(ack))) < 0)
    {
        // If interrupted by a signal handler try again.  Otherwise the monitor
        // thread probably died and we have a stale file descriptor -- abort the
        // operation.
        if (errno == EINTR)
            goto READ_AGAIN;
        return;
    }

    assert(status == sizeof(ack));
    assert(ack == op && "Invalid monitor thread response!");
}

size_t
ProcessMonitor::ReadMemory(lldb::addr_t vm_addr, void *buf, size_t size,
                           Error &error)
{
    size_t result;
    ReadOperation op(vm_addr, buf, size, error, result);
    DoOperation(&op);
    return result;
}

size_t
ProcessMonitor::WriteMemory(lldb::addr_t vm_addr, const void *buf, size_t size,
                            lldb_private::Error &error)
{
    size_t result;
    WriteOperation op(vm_addr, buf, size, error, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::ReadRegisterValue(unsigned offset, Scalar &value)
{
    bool result;
    ReadRegOperation op(offset, value, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::WriteRegisterValue(unsigned offset, const Scalar &value)
{
    bool result;
    WriteRegOperation op(offset, value, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::Resume(lldb::tid_t tid)
{
    bool result;
    ResumeOperation op(tid, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::SingleStep(lldb::tid_t tid)
{
    bool result;
    SingleStepOperation op(tid, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::GetSignalInfo(lldb::tid_t tid, void *siginfo)
{
    bool result;
    SiginfoOperation op(tid, siginfo, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::GetEventMessage(lldb::tid_t tid, unsigned long *message)
{
    bool result;
    EventMessageOperation op(tid, message, result);
    DoOperation(&op);
    return result;
}

bool
ProcessMonitor::DupDescriptor(const char *path, int fd, int flags)
{
    int target_fd = open(path, flags);

    if (target_fd == -1)
        return false;

    return (dup2(fd, target_fd) == -1) ? false : true;
}
