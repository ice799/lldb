//===-- ProcessLinux.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lldb/Core/PluginManager.h"
#include "lldb/Host/Host.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"

#include "ProcessLinux.h"
#include "ProcessMonitor.h"
#include "LinuxThread.h"

using namespace lldb;
using namespace lldb_private;

//------------------------------------------------------------------------------
// Static functions.

Process*
ProcessLinux::CreateInstance(Target& target, Listener &listener)
{
    return new ProcessLinux(target, listener);
}

void
ProcessLinux::Initialize()
{
    static bool g_initialized = false;

    if (!g_initialized)
    {
        PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                      GetPluginDescriptionStatic(),
                                      CreateInstance);
        g_initialized = true;
    }
}

void
ProcessLinux::Terminate()
{
}

const char *
ProcessLinux::GetPluginNameStatic()
{
    return "plugin.process.linux";
}

const char *
ProcessLinux::GetPluginDescriptionStatic()
{
    return "Process plugin for Linux";
}


//------------------------------------------------------------------------------
// Constructors and destructors.

ProcessLinux::ProcessLinux(Target& target, Listener &listener)
    : Process(target, listener),
      m_monitor(NULL)
{
    // FIXME: Putting this code in the ctor and saving the byte order in a
    // member variable is a hack to avoid const qual issues in GetByteOrder.
    ObjectFile *obj_file = GetTarget().GetExecutableModule()->GetObjectFile();
    m_byte_order = obj_file->GetByteOrder();

    UpdateLoadedSections();
}

ProcessLinux::~ProcessLinux()
{
    delete m_monitor;
}

//------------------------------------------------------------------------------
// Process protocol.

bool
ProcessLinux::CanDebug(Target &target)
{
    // For now we are just making sure the file exists for a given module
    ModuleSP exe_module_sp(target.GetExecutableModule());
    if (exe_module_sp.get())
        return exe_module_sp->GetFileSpec().Exists();
    return false;
}

Error
ProcessLinux::DoAttachToProcessWithID(lldb::pid_t pid)
{
    return Error(1, eErrorTypeGeneric);
}

Error
ProcessLinux::DoLaunch(Module *module,
                       char const *argv[],
                       char const *envp[],
                       const char *stdin_path,
                       const char *stdout_path,
                       const char *stderr_path)
{
    // FIXME: Implement a syncronization point between this thread and the
    // monitor thread.
    Error error;
    assert(m_monitor == NULL);

    SetPrivateState(eStateLaunching);
    m_monitor = new ProcessMonitor(this, module,
                                   argv, envp,
                                   stdin_path, stdout_path, stderr_path,
                                   error);
    if (!error.Success())
        return error;

    return error;
}

Error
ProcessLinux::DoResume()
{
    assert(GetPrivateState() == eStateStopped && "Bad state for DoResume!");

    // Set our state to running.  This ensures inferior threads do not post a
    // state change first.
    SetPrivateState(eStateRunning);

    bool did_resume = false;
    uint32_t thread_count = m_thread_list.GetSize(false);
    for (uint32_t i = 0; i < thread_count; ++i)
    {
        LinuxThread *thread = static_cast<LinuxThread*>(
            m_thread_list.GetThreadAtIndex(i, false).get());
        did_resume = thread->Resume() || did_resume;
    }
    assert(did_resume && "Process resume failed!");

    return Error();
}

Error
ProcessLinux::DoHalt()
{
    return Error(1, eErrorTypeGeneric);
}

Error
ProcessLinux::DoDetach()
{
    return Error(1, eErrorTypeGeneric);
}

Error
ProcessLinux::DoSignal(int signal)
{
    return Error(1, eErrorTypeGeneric);
}

Error
ProcessLinux::DoDestroy()
{
    Error error;
    // Once the kill signal is sent to the inferrior our signal thread will
    // catch the child termination and update the process state.
    if (!GetMonitor().KillProcess()) 
    {
        error.SetErrorToGenericError();
        error.SetErrorString("Process termination failed.");
    }

    return error;
}

void
ProcessLinux::SendMessage(const ProcessMessage &message)
{
    Mutex::Locker lock(m_message_mutex);
    m_message_queue.push(message);

    switch (message.GetKind())
    {
    default:
        SetPrivateState(eStateStopped);
        break;

    case ProcessMessage::eExitMessage:
        SetExitStatus(message.GetExitStatus(), NULL);
        break;

    case ProcessMessage::eSignalMessage:
        SetExitStatus(-1, NULL);
        break;
    }
}

void
ProcessLinux::RefreshStateAfterStop()
{
    Mutex::Locker lock(m_message_mutex);
    if (m_message_queue.empty())
        return;

    ProcessMessage &message = m_message_queue.front();

    // Resolve the thread this message corresponds to.
    lldb::tid_t tid = message.GetTID();
    LinuxThread *thread = static_cast<LinuxThread*>(
        GetThreadList().FindThreadByID(tid, false).get());
    
    switch (message.GetKind())
    {
    default:
        assert(false && "Unexpected message kind!");
        break;
        
    case ProcessMessage::eExitMessage:
    case ProcessMessage::eSignalMessage:
        thread->ExitNotify();
        break;
        
    case ProcessMessage::eTraceMessage:
        thread->TraceNotify();
        break;
        
    case ProcessMessage::eBreakpointMessage:
        thread->BreakNotify();
        break;
    }

    m_message_queue.pop();
}

bool
ProcessLinux::IsAlive()
{
    StateType state = GetPrivateState();
    return state != eStateExited && state != eStateInvalid;
}

size_t
ProcessLinux::DoReadMemory(addr_t vm_addr,
                           void *buf, size_t size, Error &error)
{
    return m_monitor->ReadMemory(vm_addr, buf, size, error);
}

size_t
ProcessLinux::DoWriteMemory(addr_t vm_addr, const void *buf, size_t size,
                            Error &error)
{
    return m_monitor->WriteMemory(vm_addr, buf, size, error);
}

addr_t
ProcessLinux::DoAllocateMemory(size_t size, uint32_t permissions,
                               Error &error)
{
    return 0;
}

addr_t
ProcessLinux::AllocateMemory(size_t size, uint32_t permissions, Error &error)
{
    return 0;
}

Error
ProcessLinux::DoDeallocateMemory(lldb::addr_t ptr)
{
    return Error(1, eErrorTypeGeneric);
}

size_t
ProcessLinux::GetSoftwareBreakpointTrapOpcode(BreakpointSite* bp_site)
{
    // FIXME: This is i386/x86_64 specific for now.
    static const uint8_t g_i386_opcode[] = { 0xCC };

    const uint8_t *opcode = g_i386_opcode;
    size_t opcode_size = sizeof(g_i386_opcode);

    bp_site->SetTrapOpcode(opcode, opcode_size);

    return opcode_size;
}

Error
ProcessLinux::EnableBreakpoint(BreakpointSite *bp_site)
{
    return EnableSoftwareBreakpoint(bp_site);
}

Error
ProcessLinux::DisableBreakpoint(BreakpointSite *bp_site)
{
    return DisableSoftwareBreakpoint(bp_site);
}

uint32_t
ProcessLinux::UpdateThreadListIfNeeded()
{
    // Do not allow recursive updates.
    return m_thread_list.GetSize(false);
}

ByteOrder
ProcessLinux::GetByteOrder() const
{
    // FIXME: We should be able to extract this value directly.  See comment in
    // ProcessLinux().
    return m_byte_order;
}

//------------------------------------------------------------------------------
// ProcessInterface protocol.

const char *
ProcessLinux::GetPluginName()
{
    return "process.linux";
}

const char *
ProcessLinux::GetShortPluginName()
{
    return "process.linux";
}

uint32_t
ProcessLinux::GetPluginVersion()
{
    return 1;
}

void
ProcessLinux::GetPluginCommandHelp(const char *command, Stream *strm)
{
}

Error
ProcessLinux::ExecutePluginCommand(Args &command, Stream *strm)
{
    return Error(1, eErrorTypeGeneric);
}

Log *
ProcessLinux::EnablePluginLogging(Stream *strm, Args &command)
{
    return NULL;
}

//------------------------------------------------------------------------------

void
ProcessLinux::UpdateLoadedSections()
{
    ObjectFile *obj_file = GetTarget().GetExecutableModule()->GetObjectFile();
    SectionList *sections = obj_file->GetSectionList();

    // FIXME: SectionList provides iterator types, but no begin/end methods.
    size_t num_sections = sections->GetSize();
    for (unsigned i = 0; i < num_sections; ++i)
    {
        Section *section = sections->GetSectionAtIndex(i).get();

        lldb::addr_t new_load_addr = section->GetFileAddress();
        lldb::addr_t old_load_addr = GetSectionLoadAddress(section);

        if (old_load_addr == LLDB_INVALID_ADDRESS ||
            old_load_addr != new_load_addr)
            SectionLoaded(section, new_load_addr);
    }
}

