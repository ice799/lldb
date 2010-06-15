//===-- ProcessGDBRemote.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

// C++ Includes
#include <algorithm>
#include <map>

// Other libraries and framework includes

#include "lldb/Breakpoint/WatchpointLocation.h"
#include "lldb/Interpreter/Args.h"
#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/ConnectionFileDescriptor.h"
#include "lldb/Core/FileSpec.h"
#include "lldb/Core/InputReader.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/State.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Core/Timer.h"
#include "lldb/Host/TimeValue.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/DynamicLoader.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/TargetList.h"
#include "lldb/Utility/PseudoTerminal.h"

// Project includes
#include "lldb/Host/Host.h"
#include "StringExtractorGDBRemote.h"
#include "GDBRemoteRegisterContext.h"
#include "ProcessGDBRemote.h"
#include "ProcessGDBRemoteLog.h"
#include "ThreadGDBRemote.h"
#include "libunwind.h"
#include "MacOSXLibunwindCallbacks.h"

#if defined (__i386__) || defined (__x86_64__)
#define MACH_EXC_DATA0_SOFTWARE_BREAKPOINT EXC_I386_BPT
#define MACH_EXC_DATA0_TRACE EXC_I386_SGL
#elif defined (__powerpc__) || defined (__ppc__) || defined (__ppc64__)
#define MACH_EXC_DATA0_SOFTWARE_BREAKPOINT EXC_PPC_BREAKPOINT
#elif defined (__arm__)
#define MACH_EXC_DATA0_SOFTWARE_BREAKPOINT EXC_ARM_BREAKPOINT
#endif


#define DEBUGSERVER_BASENAME    "debugserver"
using namespace lldb;
using namespace lldb_private;

static inline uint16_t
get_random_port ()
{
    return (arc4random() % (UINT16_MAX - 1000u)) + 1000u;
}


const char *
ProcessGDBRemote::GetPluginNameStatic()
{
    return "process.gdb-remote";
}

const char *
ProcessGDBRemote::GetPluginDescriptionStatic()
{
    return "GDB Remote protocol based debugging plug-in.";
}

void
ProcessGDBRemote::Terminate()
{
    PluginManager::UnregisterPlugin (ProcessGDBRemote::CreateInstance);
}


Process*
ProcessGDBRemote::CreateInstance (Target &target, Listener &listener)
{
    return new ProcessGDBRemote (target, listener);
}

bool
ProcessGDBRemote::CanDebug(Target &target)
{
    // For now we are just making sure the file exists for a given module
    ModuleSP exe_module_sp(target.GetExecutableModule());
    if (exe_module_sp.get())
        return exe_module_sp->GetFileSpec().Exists();
    return false;
}

//----------------------------------------------------------------------
// ProcessGDBRemote constructor
//----------------------------------------------------------------------
ProcessGDBRemote::ProcessGDBRemote(Target& target, Listener &listener) :
    Process (target, listener),
    m_dynamic_loader_ap (),
    m_byte_order (eByteOrderHost),
    m_flags (0),
    m_stdio_communication ("gdb-remote.stdio"),
    m_stdio_mutex (Mutex::eMutexTypeRecursive),
    m_stdout_data (),
    m_arch_spec (),
    m_gdb_comm(),
    m_debugserver_pid (LLDB_INVALID_PROCESS_ID),
    m_debugserver_monitor (0),
    m_register_info (),
    m_curr_tid (LLDB_INVALID_THREAD_ID),
    m_curr_tid_run (LLDB_INVALID_THREAD_ID),
    m_async_broadcaster ("lldb.process.gdb-remote.async-broadcaster"),
    m_async_thread (LLDB_INVALID_HOST_THREAD),
    m_z0_supported (1),
    m_continue_packet(),
    m_dispatch_queue_offsets_addr (LLDB_INVALID_ADDRESS),
    m_libunwind_target_type (UNW_TARGET_UNSPECIFIED),
    m_libunwind_addr_space (NULL),
    m_waiting_for_attach (false),
    m_packet_timeout (1),
    m_max_memory_size (512)
{
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
ProcessGDBRemote::~ProcessGDBRemote()
{
    //  m_mach_process.UnregisterNotificationCallbacks (this);
    Clear();
}

//----------------------------------------------------------------------
// PluginInterface
//----------------------------------------------------------------------
const char *
ProcessGDBRemote::GetPluginName()
{
    return "Process debugging plug-in that uses the GDB remote protocol";
}

const char *
ProcessGDBRemote::GetShortPluginName()
{
    return GetPluginNameStatic();
}

uint32_t
ProcessGDBRemote::GetPluginVersion()
{
    return 1;
}

void
ProcessGDBRemote::GetPluginCommandHelp (const char *command, Stream *strm)
{
    strm->Printf("TODO: fill this in\n");
}

Error
ProcessGDBRemote::ExecutePluginCommand (Args &command, Stream *strm)
{
    Error error;
    error.SetErrorString("No plug-in commands are currently supported.");
    return error;
}

Log *
ProcessGDBRemote::EnablePluginLogging (Stream *strm, Args &command)
{
    return NULL;
}

void
ProcessGDBRemote::BuildDynamicRegisterInfo ()
{
    char register_info_command[64];
    m_register_info.Clear();
    StringExtractorGDBRemote::Type packet_type = StringExtractorGDBRemote::eResponse;
    uint32_t reg_offset = 0;
    uint32_t reg_num = 0;
    for (; packet_type == StringExtractorGDBRemote::eResponse; ++reg_num)
    {
        ::snprintf (register_info_command, sizeof(register_info_command), "qRegisterInfo%x", reg_num);
        StringExtractorGDBRemote response;
        if (m_gdb_comm.SendPacketAndWaitForResponse(register_info_command, response, 2, false))
        {
            packet_type = response.GetType();
            if (packet_type == StringExtractorGDBRemote::eResponse)
            {
                std::string name;
                std::string value;
                ConstString reg_name;
                ConstString alt_name;
                ConstString set_name;
                RegisterInfo reg_info = { NULL,                 // Name
                    NULL,                 // Alt name
                    0,                    // byte size
                    reg_offset,           // offset
                    eEncodingUint,        // encoding
                    eFormatHex,           // formate
                    reg_num,              // native register number
                    {
                        LLDB_INVALID_REGNUM, // GCC reg num
                        LLDB_INVALID_REGNUM, // DWARF reg num
                        LLDB_INVALID_REGNUM, // generic reg num
                        reg_num              // GDB reg num
                    }
                };

                while (response.GetNameColonValue(name, value))
                {
                    if (name.compare("name") == 0)
                    {
                        reg_name.SetCString(value.c_str());
                    }
                    else if (name.compare("alt-name") == 0)
                    {
                        alt_name.SetCString(value.c_str());
                    }
                    else if (name.compare("bitsize") == 0)
                    {
                        reg_info.byte_size = Args::StringToUInt32(value.c_str(), 0, 0) / CHAR_BIT;
                    }
                    else if (name.compare("offset") == 0)
                    {
                        uint32_t offset = Args::StringToUInt32(value.c_str(), UINT32_MAX, 0);
                        if (reg_offset != offset)
                        {
                            reg_offset = offset;
                        }
                    }
                    else if (name.compare("encoding") == 0)
                    {
                        if (value.compare("uint") == 0)
                            reg_info.encoding = eEncodingUint;
                        else if (value.compare("sint") == 0)
                            reg_info.encoding = eEncodingSint;
                        else if (value.compare("ieee754") == 0)
                            reg_info.encoding = eEncodingIEEE754;
                        else if (value.compare("vector") == 0)
                            reg_info.encoding = eEncodingVector;
                    }
                    else if (name.compare("format") == 0)
                    {
                        if (value.compare("binary") == 0)
                            reg_info.format = eFormatBinary;
                        else if (value.compare("decimal") == 0)
                            reg_info.format = eFormatDecimal;
                        else if (value.compare("hex") == 0)
                            reg_info.format = eFormatHex;
                        else if (value.compare("float") == 0)
                            reg_info.format = eFormatFloat;
                        else if (value.compare("vector-sint8") == 0)
                            reg_info.format = eFormatVectorOfSInt8;
                        else if (value.compare("vector-uint8") == 0)
                            reg_info.format = eFormatVectorOfUInt8;
                        else if (value.compare("vector-sint16") == 0)
                            reg_info.format = eFormatVectorOfSInt16;
                        else if (value.compare("vector-uint16") == 0)
                            reg_info.format = eFormatVectorOfUInt16;
                        else if (value.compare("vector-sint32") == 0)
                            reg_info.format = eFormatVectorOfSInt32;
                        else if (value.compare("vector-uint32") == 0)
                            reg_info.format = eFormatVectorOfUInt32;
                        else if (value.compare("vector-float32") == 0)
                            reg_info.format = eFormatVectorOfFloat32;
                        else if (value.compare("vector-uint128") == 0)
                            reg_info.format = eFormatVectorOfUInt128;
                    }
                    else if (name.compare("set") == 0)
                    {
                        set_name.SetCString(value.c_str());
                    }
                    else if (name.compare("gcc") == 0)
                    {
                        reg_info.kinds[eRegisterKindGCC] = Args::StringToUInt32(value.c_str(), LLDB_INVALID_REGNUM, 0);
                    }
                    else if (name.compare("dwarf") == 0)
                    {
                        reg_info.kinds[eRegisterKindDWARF] = Args::StringToUInt32(value.c_str(), LLDB_INVALID_REGNUM, 0);
                    }
                    else if (name.compare("generic") == 0)
                    {
                        if (value.compare("pc") == 0)
                            reg_info.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_PC;
                        else if (value.compare("sp") == 0)
                            reg_info.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_SP;
                        else if (value.compare("fp") == 0)
                            reg_info.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FP;
                        else if (value.compare("ra") == 0)
                            reg_info.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_RA;
                        else if (value.compare("flags") == 0)
                            reg_info.kinds[eRegisterKindGeneric] = LLDB_REGNUM_GENERIC_FLAGS;
                    }
                }

                reg_info.byte_offset = reg_offset;
                assert (reg_info.byte_size != 0);
                reg_offset += reg_info.byte_size;
                m_register_info.AddRegister(reg_info, reg_name, alt_name, set_name);
            }
        }
        else
        {
            packet_type = StringExtractorGDBRemote::eError;
        }
    }

    if (reg_num == 0)
    {
        // We didn't get anything. See if we are debugging ARM and fill with
        // a hard coded register set until we can get an updated debugserver
        // down on the devices.
        ArchSpec arm_arch ("arm");
        if (GetTarget().GetArchitecture() == arm_arch)
            m_register_info.HardcodeARMRegisters();
    }
    m_register_info.Finalize ();
}

Error
ProcessGDBRemote::WillLaunch (Module* module)
{
    return WillLaunchOrAttach ();
}

Error
ProcessGDBRemote::WillAttach (lldb::pid_t pid)
{
    return WillLaunchOrAttach ();
}

Error
ProcessGDBRemote::WillAttach (const char *process_name, bool wait_for_launch)
{
    return WillLaunchOrAttach ();
}

Error
ProcessGDBRemote::WillLaunchOrAttach ()
{
    Error error;
    // TODO: this is hardcoded for macosx right now. We need this to be more dynamic
    m_dynamic_loader_ap.reset(DynamicLoader::FindPlugin(this, "dynamic-loader.macosx-dyld"));

    if (m_dynamic_loader_ap.get() == NULL)
        error.SetErrorString("unable to find the dynamic loader named 'dynamic-loader.macosx-dyld'");
    m_stdio_communication.Clear ();
    
    return error;
}

//----------------------------------------------------------------------
// Process Control
//----------------------------------------------------------------------
Error
ProcessGDBRemote::DoLaunch
(
    Module* module,
    char const *argv[],
    char const *envp[],
    const char *stdin_path,
    const char *stdout_path,
    const char *stderr_path
)
{
    //  ::LogSetBitMask (GDBR_LOG_DEFAULT);
    //  ::LogSetOptions (LLDB_LOG_OPTION_THREADSAFE | LLDB_LOG_OPTION_PREPEND_TIMESTAMP | LLDB_LOG_OPTION_PREPEND_PROC_AND_THREAD);
    //  ::LogSetLogFile ("/dev/stdout");
    Error error;

    ObjectFile * object_file = module->GetObjectFile();
    if (object_file)
    {
        ArchSpec inferior_arch(module->GetArchitecture());
        char host_port[128];
        snprintf (host_port, sizeof(host_port), "localhost:%u", get_random_port ());

        bool start_debugserver_with_inferior_args = false;
        if (start_debugserver_with_inferior_args)
        {
            // We want to launch debugserver with the inferior program and its
            // arguments on the command line. We should only do this if we
            // the GDB server we are talking to doesn't support the 'A' packet.
            error = StartDebugserverProcess (host_port,
                                             argv,
                                             envp,
                                             NULL, //stdin_path,
                                             LLDB_INVALID_PROCESS_ID,
                                             NULL, false,
                                             inferior_arch);
            if (error.Fail())
                return error;

            error = ConnectToDebugserver (host_port);
            if (error.Success())
            {
                SetID (m_gdb_comm.GetCurrentProcessID (m_packet_timeout));
            }
        }
        else
        {
            error = StartDebugserverProcess (host_port,
                                             NULL,
                                             NULL,
                                             NULL, //stdin_path,
                                             LLDB_INVALID_PROCESS_ID,
                                             NULL, false,
                                             inferior_arch);
            if (error.Fail())
                return error;

            error = ConnectToDebugserver (host_port);
            if (error.Success())
            {
                // Send the environment and the program + arguments after we connect
                if (envp)
                {
                    const char *env_entry;
                    for (int i=0; (env_entry = envp[i]); ++i)
                    {
                        if (m_gdb_comm.SendEnvironmentPacket(env_entry, m_packet_timeout) != 0)
                            break;
                    }
                }

                const uint32_t arg_timeout_seconds = 10;
                int arg_packet_err = m_gdb_comm.SendArgumentsPacket (argv, arg_timeout_seconds);
                if (arg_packet_err == 0)
                {
                    std::string error_str;
                    if (m_gdb_comm.GetLaunchSuccess (m_packet_timeout, error_str))
                    {
                        SetID (m_gdb_comm.GetCurrentProcessID (m_packet_timeout));
                    }
                    else
                    {
                        error.SetErrorString (error_str.c_str());
                    }
                }
                else
                {
                    error.SetErrorStringWithFormat("'A' packet returned an error: %i.\n", arg_packet_err);
                }
                
                SetID (m_gdb_comm.GetCurrentProcessID (m_packet_timeout));
            }
        }

        if (GetID() == LLDB_INVALID_PROCESS_ID)
        {
            KillDebugserverProcess ();
            return error;
        }
    
        StringExtractorGDBRemote response;
        if (m_gdb_comm.SendPacketAndWaitForResponse("?", 1, response, m_packet_timeout, false))
            SetPrivateState (SetThreadStopInfo (response));

    }
    else
    {
        // Set our user ID to an invalid process ID.
        SetID(LLDB_INVALID_PROCESS_ID);
        error.SetErrorStringWithFormat("Failed to get object file from '%s' for arch %s.\n", module->GetFileSpec().GetFilename().AsCString(), module->GetArchitecture().AsCString());
    }

    // Return the process ID we have
    return error;
}


Error
ProcessGDBRemote::ConnectToDebugserver (const char *host_port)
{
    Error error;
    // Sleep and wait a bit for debugserver to start to listen...
    std::auto_ptr<ConnectionFileDescriptor> conn_ap(new ConnectionFileDescriptor());
    if (conn_ap.get())
    {
        std::string connect_url("connect://");
        connect_url.append (host_port);
        const uint32_t max_retry_count = 50;
        uint32_t retry_count = 0;
        while (!m_gdb_comm.IsConnected())
        {
            if (conn_ap->Connect(connect_url.c_str(), &error) == eConnectionStatusSuccess)
            {
                m_gdb_comm.SetConnection (conn_ap.release());
                break;
            }
            retry_count++;

            if (retry_count >= max_retry_count)
                break;

            usleep (100000);
        }
    }

    if (!m_gdb_comm.IsConnected())
    {
        if (error.Success())
            error.SetErrorString("not connected to remote gdb server");
        return error;
    }

    m_gdb_comm.SetAckMode (true);
    if (m_gdb_comm.StartReadThread(&error))
    {
        // Send an initial ack
        m_gdb_comm.SendAck('+');

        if (m_debugserver_pid != LLDB_INVALID_PROCESS_ID)
            m_debugserver_monitor = Host::StartMonitoringChildProcess (MonitorDebugserverProcess,
                                                                       (void*)(intptr_t)GetID(),    // Pass the inferior pid in the thread argument (which is a void *)
                                                                       m_debugserver_pid,
                                                                       false);

        StringExtractorGDBRemote response;
        if (m_gdb_comm.SendPacketAndWaitForResponse("QStartNoAckMode", response, 1, false))
        {
            if (response.IsOKPacket())
                m_gdb_comm.SetAckMode (false);
        }

        BuildDynamicRegisterInfo ();
    }
    return error;
}

void
ProcessGDBRemote::DidLaunchOrAttach ()
{
    ProcessGDBRemoteLog::LogIf (GDBR_LOG_PROCESS, "ProcessGDBRemote::DidLaunch()");
    if (GetID() == LLDB_INVALID_PROCESS_ID)
    {
        m_dynamic_loader_ap.reset();
    }
    else
    {
        m_dispatch_queue_offsets_addr = LLDB_INVALID_ADDRESS;

        Module * exe_module = GetTarget().GetExecutableModule ().get();
        assert(exe_module);

        m_arch_spec = exe_module->GetArchitecture();

        ObjectFile *exe_objfile = exe_module->GetObjectFile();
        assert(exe_objfile);

        m_byte_order = exe_objfile->GetByteOrder();
        assert (m_byte_order != eByteOrderInvalid);

        StreamString strm;

        ArchSpec inferior_arch;
        // See if the GDB server supports the qHostInfo information
        const char *vendor = m_gdb_comm.GetVendorString().AsCString();
        const char *os_type = m_gdb_comm.GetOSString().AsCString();
        
        if (m_arch_spec.IsValid() && m_arch_spec == ArchSpec ("arm"))
        {
            // For ARM we can't trust the arch of the process as it could
            // have an armv6 object file, but be running on armv7 kernel.
            inferior_arch = m_gdb_comm.GetHostArchitecture();
        }
        
        if (!inferior_arch.IsValid())
            inferior_arch = m_arch_spec;

        if (vendor == NULL)
            vendor = Host::GetVendorString().AsCString("apple");
        
        if (os_type == NULL)
            os_type = Host::GetOSString().AsCString("darwin");

        strm.Printf ("%s-%s-%s", inferior_arch.AsCString(), vendor, os_type);

        std::transform (strm.GetString().begin(), 
                        strm.GetString().end(), 
                        strm.GetString().begin(), 
                        ::tolower);

        m_target_triple.SetCString(strm.GetString().c_str());
    }
}

void
ProcessGDBRemote::DidLaunch ()
{
    DidLaunchOrAttach ();
    if (m_dynamic_loader_ap.get())
        m_dynamic_loader_ap->DidLaunch();
}

Error
ProcessGDBRemote::DoAttach (pid_t attach_pid)
{
    Error error;
    // Clear out and clean up from any current state
    Clear();
    // HACK: require arch be set correctly at the target level until we can
    // figure out a good way to determine the arch of what we are attaching to
    m_arch_spec = m_target.GetArchitecture();

    //Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet (GDBR_LOG_PROCESS);
    if (attach_pid != LLDB_INVALID_PROCESS_ID)
    {
        SetPrivateState (eStateAttaching);
        char host_port[128];
        snprintf (host_port, sizeof(host_port), "localhost:%u", get_random_port ());
        error = StartDebugserverProcess (host_port,
                                         NULL,
                                         NULL,
                                         NULL,
                                         LLDB_INVALID_PROCESS_ID,
                                         NULL, false,
                                         m_arch_spec);
        
        if (error.Fail())
        {
            const char *error_string = error.AsCString();
            if (error_string == NULL)
                error_string = "unable to launch " DEBUGSERVER_BASENAME;

            SetExitStatus (-1, error_string);
        }
        else
        {
            error = ConnectToDebugserver (host_port);
            if (error.Success())
            {
                char packet[64];
                const int packet_len = ::snprintf (packet, sizeof(packet), "vAttach;%x", attach_pid);
                StringExtractorGDBRemote response;
                StateType stop_state = m_gdb_comm.SendContinuePacketAndWaitForResponse (this, 
                                                                                        packet, 
                                                                                        packet_len, 
                                                                                        response);
                switch (stop_state)
                {
                case eStateStopped:
                case eStateCrashed:
                case eStateSuspended:
                    SetID (attach_pid);
                    m_last_stop_packet = response;
                    m_last_stop_packet.SetFilePos (0);
                    SetPrivateState (stop_state);
                    break;

                case eStateExited:
                    m_last_stop_packet = response;
                    m_last_stop_packet.SetFilePos (0);
                    response.SetFilePos(1);
                    SetExitStatus(response.GetHexU8(), NULL);
                    break;

                default:
                    SetExitStatus(-1, "unable to attach to process");
                    break;
                }

            }
        }
    }

    lldb::pid_t pid = GetID();
    if (pid == LLDB_INVALID_PROCESS_ID)
    {
        KillDebugserverProcess();
    }
    return error;
}

size_t
ProcessGDBRemote::AttachInputReaderCallback
(
    void *baton, 
    InputReader *reader, 
    lldb::InputReaderAction notification,
    const char *bytes, 
    size_t bytes_len
)
{
    if (notification == eInputReaderGotToken)
    {
        ProcessGDBRemote *gdb_process = (ProcessGDBRemote *)baton;
        if (gdb_process->m_waiting_for_attach)
            gdb_process->m_waiting_for_attach = false;
        reader->SetIsDone(true);
        return 1;
    }
    return 0;
}

Error
ProcessGDBRemote::DoAttach (const char *process_name, bool wait_for_launch)
{
    Error error;
    // Clear out and clean up from any current state
    Clear();
    // HACK: require arch be set correctly at the target level until we can
    // figure out a good way to determine the arch of what we are attaching to
    m_arch_spec = m_target.GetArchitecture();

    //Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet (GDBR_LOG_PROCESS);
    if (process_name && process_name[0])
    {

        SetPrivateState (eStateAttaching);
        char host_port[128];
        snprintf (host_port, sizeof(host_port), "localhost:%u", get_random_port ());
        error = StartDebugserverProcess (host_port,
                                         NULL,
                                         NULL,
                                         NULL,
                                         LLDB_INVALID_PROCESS_ID,
                                         NULL, false,
                                         m_arch_spec);
        if (error.Fail())
        {
            const char *error_string = error.AsCString();
            if (error_string == NULL)
                error_string = "unable to launch " DEBUGSERVER_BASENAME;

            SetExitStatus (-1, error_string);
        }
        else
        {
            error = ConnectToDebugserver (host_port);
            if (error.Success())
            {
                StreamString packet;
                
                packet.PutCString("vAttach");
                if (wait_for_launch)
                    packet.PutCString("Wait");
                packet.PutChar(';');
                packet.PutBytesAsRawHex8(process_name, strlen(process_name), eByteOrderHost, eByteOrderHost);
                StringExtractorGDBRemote response;
                StateType stop_state = m_gdb_comm.SendContinuePacketAndWaitForResponse (this, 
                                                                                        packet.GetData(), 
                                                                                        packet.GetSize(), 
                                                                                        response);
                switch (stop_state)
                {
                case eStateStopped:
                case eStateCrashed:
                case eStateSuspended:
                    SetID (m_gdb_comm.GetCurrentProcessID(m_packet_timeout));
                    m_last_stop_packet = response;
                    m_last_stop_packet.SetFilePos (0);
                    SetPrivateState (stop_state);
                    break;

                case eStateExited:
                    m_last_stop_packet = response;
                    m_last_stop_packet.SetFilePos (0);
                    response.SetFilePos(1);
                    SetExitStatus(response.GetHexU8(), NULL);
                    break;

                default:
                    SetExitStatus(-1, "unable to attach to process");
                    break;
                }
            }
        }
    }

    lldb::pid_t pid = GetID();
    if (pid == LLDB_INVALID_PROCESS_ID)
    {
        KillDebugserverProcess();
    }
    return error;
}

//                              
//        if (wait_for_launch)
//        {
//            InputReaderSP reader_sp (new InputReader());
//            StreamString instructions;
//            instructions.Printf("Hit any key to cancel waiting for '%s' to launch...", process_name);
//            error = reader_sp->Initialize (AttachInputReaderCallback, // callback
//                                                this, // baton
//                                                eInputReaderGranularityByte,
//                                                NULL, // End token
//                                                false);
//            
//            StringExtractorGDBRemote response;
//            m_waiting_for_attach = true;
//            FILE *reader_out_fh = reader_sp->GetOutputFileHandle();
//            while (m_waiting_for_attach)
//            {
//                // Wait for one second for the stop reply packet
//                if (m_gdb_comm.WaitForPacket(response, 1))
//                {
//                    // Got some sort of packet, see if it is the stop reply packet?
//                    char ch = response.GetChar(0);
//                    if (ch == 'T')
//                    {
//                        m_waiting_for_attach = false;
//                    }
//                }
//                else
//                {
//                    // Put a period character every second
//                    fputc('.', reader_out_fh);
//                }
//            }
//        }
//    }
//    return GetID();
//}

void
ProcessGDBRemote::DidAttach ()
{
    DidLaunchOrAttach ();
    if (m_dynamic_loader_ap.get())
        m_dynamic_loader_ap->DidAttach();
}

Error
ProcessGDBRemote::WillResume ()
{
    m_continue_packet.Clear();
    // Start the continue packet we will use to run the target. Each thread
    // will append what it is supposed to be doing to this packet when the
    // ThreadList::WillResume() is called. If a thread it supposed
    // to stay stopped, then don't append anything to this string.
    m_continue_packet.Printf("vCont");
    return Error();
}

Error
ProcessGDBRemote::DoResume ()
{
    ProcessGDBRemoteLog::LogIf (GDBR_LOG_PROCESS, "ProcessGDBRemote::Resume()");
    m_async_broadcaster.BroadcastEvent (eBroadcastBitAsyncContinue, new EventDataBytes (m_continue_packet.GetData(), m_continue_packet.GetSize()));
    return Error();
}

size_t
ProcessGDBRemote::GetSoftwareBreakpointTrapOpcode (BreakpointSite* bp_site)
{
    const uint8_t *trap_opcode = NULL;
    uint32_t trap_opcode_size = 0;

    static const uint8_t g_arm_breakpoint_opcode[] = { 0xFE, 0xDE, 0xFF, 0xE7 };
    //static const uint8_t g_thumb_breakpooint_opcode[] = { 0xFE, 0xDE };
    static const uint8_t g_ppc_breakpoint_opcode[] = { 0x7F, 0xC0, 0x00, 0x08 };
    static const uint8_t g_i386_breakpoint_opcode[] = { 0xCC };

    ArchSpec::CPU arch_cpu = m_arch_spec.GetGenericCPUType();
    switch (arch_cpu)
    {
    case ArchSpec::eCPU_i386:
    case ArchSpec::eCPU_x86_64:
        trap_opcode = g_i386_breakpoint_opcode;
        trap_opcode_size = sizeof(g_i386_breakpoint_opcode);
        break;
    
    case ArchSpec::eCPU_arm:
        // TODO: fill this in for ARM. We need to dig up the symbol for
        // the address in the breakpoint locaiton and figure out if it is
        // an ARM or Thumb breakpoint.
        trap_opcode = g_arm_breakpoint_opcode;
        trap_opcode_size = sizeof(g_arm_breakpoint_opcode);
        break;
    
    case ArchSpec::eCPU_ppc:
    case ArchSpec::eCPU_ppc64:
        trap_opcode = g_ppc_breakpoint_opcode;
        trap_opcode_size = sizeof(g_ppc_breakpoint_opcode);
        break;

    default:
        assert(!"Unhandled architecture in ProcessMacOSX::GetSoftwareBreakpointTrapOpcode()");
        break;
    }

    if (trap_opcode && trap_opcode_size)
    {
        if (bp_site->SetTrapOpcode(trap_opcode, trap_opcode_size))
            return trap_opcode_size;
    }
    return 0;
}

uint32_t
ProcessGDBRemote::UpdateThreadListIfNeeded ()
{
    // locker will keep a mutex locked until it goes out of scope
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet (GDBR_LOG_THREAD);
    if (log && log->GetMask().IsSet(GDBR_LOG_VERBOSE))
        log->Printf ("ProcessGDBRemote::%s (pid = %i)", __FUNCTION__, GetID());

    const uint32_t stop_id = GetStopID();
    if (m_thread_list.GetSize(false) == 0 || stop_id != m_thread_list.GetStopID())
    {
        // Update the thread list's stop id immediately so we don't recurse into this function.
        ThreadList curr_thread_list (this);
        curr_thread_list.SetStopID(stop_id);

        Error err;
        StringExtractorGDBRemote response;
        for (m_gdb_comm.SendPacketAndWaitForResponse("qfThreadInfo", response, 1, false);
             response.IsNormalPacket();
             m_gdb_comm.SendPacketAndWaitForResponse("qsThreadInfo", response, 1, false))
        {
            char ch = response.GetChar();
            if (ch == 'l')
                break;
            if (ch == 'm')
            {
                do
                {
                    tid_t tid = response.GetHexMaxU32(false, LLDB_INVALID_THREAD_ID);

                    if (tid != LLDB_INVALID_THREAD_ID)
                    {
                        ThreadSP thread_sp (GetThreadList().FindThreadByID (tid, false));
                        if (thread_sp)
                            thread_sp->GetRegisterContext()->Invalidate();
                        else
                            thread_sp.reset (new ThreadGDBRemote (*this, tid));
                        curr_thread_list.AddThread(thread_sp);
                    }

                    ch = response.GetChar();
                } while (ch == ',');
            }
        }

        m_thread_list = curr_thread_list;

        SetThreadStopInfo (m_last_stop_packet);
    }
    return GetThreadList().GetSize(false);
}


StateType
ProcessGDBRemote::SetThreadStopInfo (StringExtractor& stop_packet)
{
    const char stop_type = stop_packet.GetChar();
    switch (stop_type)
    {
    case 'T':
    case 'S':
        {
            // Stop with signal and thread info
            const uint8_t signo = stop_packet.GetHexU8();
            std::string name;
            std::string value;
            std::string thread_name;
            uint32_t exc_type = 0;
            std::vector<uint64_t> exc_data;
            uint32_t tid = LLDB_INVALID_THREAD_ID;
            addr_t thread_dispatch_qaddr = LLDB_INVALID_ADDRESS;
            uint32_t exc_data_count = 0;
            while (stop_packet.GetNameColonValue(name, value))
            {
                if (name.compare("metype") == 0)
                {
                    // exception type in big endian hex
                    exc_type = Args::StringToUInt32 (value.c_str(), 0, 16);
                }
                else if (name.compare("mecount") == 0)
                {
                    // exception count in big endian hex
                    exc_data_count = Args::StringToUInt32 (value.c_str(), 0, 16);
                }
                else if (name.compare("medata") == 0)
                {
                    // exception data in big endian hex
                    exc_data.push_back(Args::StringToUInt64 (value.c_str(), 0, 16));
                }
                else if (name.compare("thread") == 0)
                {
                    // thread in big endian hex
                    tid = Args::StringToUInt32 (value.c_str(), 0, 16);
                }
                else if (name.compare("name") == 0)
                {
                    thread_name.swap (value);
                }
                else if (name.compare("dispatchqaddr") == 0)
                {
                    thread_dispatch_qaddr = Args::StringToUInt64 (value.c_str(), 0, 16);
                }
            }
            ThreadSP thread_sp (m_thread_list.FindThreadByID(tid, false));

            if (thread_sp)
            {
                ThreadGDBRemote *gdb_thread = static_cast<ThreadGDBRemote *> (thread_sp.get());

                gdb_thread->SetThreadDispatchQAddr (thread_dispatch_qaddr);
                gdb_thread->SetName (thread_name.empty() ? thread_name.c_str() : NULL);
                Thread::StopInfo& stop_info = gdb_thread->GetStopInfoRef();
                gdb_thread->SetStopInfoStopID (GetStopID());
                if (exc_type != 0)
                {
                    if (exc_type == EXC_SOFTWARE && exc_data.size() == 2 && exc_data[0] == EXC_SOFT_SIGNAL)
                    {
                        stop_info.SetStopReasonWithSignal(exc_data[1]);
                    }
#if defined (MACH_EXC_DATA0_SOFTWARE_BREAKPOINT)
                    else if (exc_type == EXC_BREAKPOINT && exc_data[0] == MACH_EXC_DATA0_SOFTWARE_BREAKPOINT)
                    {
                        addr_t pc = gdb_thread->GetRegisterContext()->GetPC();
                        user_id_t break_id = GetBreakpointSiteList().FindIDByAddress(pc);
                        if (break_id == LLDB_INVALID_BREAK_ID)
                        {
                            //log->Printf("got EXC_BREAKPOINT at 0x%llx but didn't find a breakpoint site.\n", pc);
                            stop_info.SetStopReasonWithException(exc_type, exc_data.size());
                            for (uint32_t i=0; i<exc_data.size(); ++i)
                                stop_info.SetExceptionDataAtIndex(i, exc_data[i]);
                        }
                        else
                        {
                            stop_info.Clear ();
                            stop_info.SetStopReasonWithBreakpointSiteID (break_id);
                        }
                    }
#endif
#if defined (MACH_EXC_DATA0_TRACE)
                    else if (exc_type == EXC_BREAKPOINT && exc_data[0] == MACH_EXC_DATA0_TRACE)
                    {
                        stop_info.SetStopReasonToTrace ();
                    }
#endif
                    else
                    {
                        stop_info.SetStopReasonWithException(exc_type, exc_data.size());
                        for (uint32_t i=0; i<exc_data.size(); ++i)
                            stop_info.SetExceptionDataAtIndex(i, exc_data[i]);
                    }
                }
                else if (signo)
                {
                    stop_info.SetStopReasonWithSignal(signo);
                }
                else
                {
                    stop_info.SetStopReasonToNone();
                }
            }
            return eStateStopped;
        }
        break;

    case 'W':
        // process exited
        return eStateExited;

    default:
        break;
    }
    return eStateInvalid;
}

void
ProcessGDBRemote::RefreshStateAfterStop ()
{
    // We must be attaching if we don't already have a valid architecture
    if (!m_arch_spec.IsValid())
    {
        Module *exe_module = GetTarget().GetExecutableModule().get();
        if (exe_module)
            m_arch_spec = exe_module->GetArchitecture();
    }
    // Let all threads recover from stopping and do any clean up based
    // on the previous thread state (if any).
    m_thread_list.RefreshStateAfterStop();

    // Discover new threads:
    UpdateThreadListIfNeeded ();
}

Error
ProcessGDBRemote::DoHalt ()
{
    Error error;
    if (m_gdb_comm.IsRunning())
    {
        bool timed_out = false;
        if (!m_gdb_comm.SendInterrupt (2, &timed_out))
        {
            if (timed_out)
                error.SetErrorString("timed out sending interrupt packet");
            else
                error.SetErrorString("unknown error sending interrupt packet");
        }
    }
    return error;
}

Error
ProcessGDBRemote::WillDetach ()
{
    Error error;
    const StateType state = m_private_state.GetValue();

    if (IsRunning(state))
        error.SetErrorString("Process must be stopped in order to detach.");

    return error;
}


Error
ProcessGDBRemote::DoDestroy ()
{
    Error error;
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_PROCESS);
    if (log)
        log->Printf ("ProcessGDBRemote::DoDestroy()");

    // Interrupt if our inferior is running...
    m_gdb_comm.SendInterrupt (1);
    DisableAllBreakpointSites ();
    SetExitStatus(-1, "process killed");

    StringExtractorGDBRemote response;
    if (m_gdb_comm.SendPacketAndWaitForResponse("k", response, 2, false))
    {
        if (log)
        {
            if (response.IsOKPacket())
                log->Printf ("ProcessGDBRemote::DoDestroy() kill was successful");
            else
                log->Printf ("ProcessGDBRemote::DoDestroy() kill failed: %s", response.GetStringRef().c_str());
        }
    }

    StopAsyncThread ();
    m_gdb_comm.StopReadThread();
    KillDebugserverProcess ();
    return error;
}

ByteOrder
ProcessGDBRemote::GetByteOrder () const
{
    return m_byte_order;
}

//------------------------------------------------------------------
// Process Queries
//------------------------------------------------------------------

bool
ProcessGDBRemote::IsAlive ()
{
    return m_gdb_comm.IsConnected();
}

addr_t
ProcessGDBRemote::GetImageInfoAddress()
{
    if (!m_gdb_comm.IsRunning())
    {
        StringExtractorGDBRemote response;
        if (m_gdb_comm.SendPacketAndWaitForResponse("qShlibInfoAddr", ::strlen ("qShlibInfoAddr"), response, 2, false))
        {
            if (response.IsNormalPacket())
                return response.GetHexMaxU64(false, LLDB_INVALID_ADDRESS);
        }
    }
    return LLDB_INVALID_ADDRESS;
}

DynamicLoader *
ProcessGDBRemote::GetDynamicLoader()
{
    return m_dynamic_loader_ap.get();
}

//------------------------------------------------------------------
// Process Memory
//------------------------------------------------------------------
size_t
ProcessGDBRemote::DoReadMemory (addr_t addr, void *buf, size_t size, Error &error)
{
    if (size > m_max_memory_size)
    {
        // Keep memory read sizes down to a sane limit. This function will be
        // called multiple times in order to complete the task by 
        // lldb_private::Process so it is ok to do this.
        size = m_max_memory_size;
    }

    char packet[64];
    const int packet_len = ::snprintf (packet, sizeof(packet), "m%llx,%zx", (uint64_t)addr, size);
    assert (packet_len + 1 < sizeof(packet));
    StringExtractorGDBRemote response;
    if (m_gdb_comm.SendPacketAndWaitForResponse(packet, packet_len, response, 2, true))
    {
        if (response.IsNormalPacket())
        {
            error.Clear();
            return response.GetHexBytes(buf, size, '\xdd');
        }
        else if (response.IsErrorPacket())
            error.SetErrorStringWithFormat("gdb remote returned an error: %s", response.GetStringRef().c_str());
        else if (response.IsUnsupportedPacket())
            error.SetErrorStringWithFormat("'%s' packet unsupported", packet);
        else
            error.SetErrorStringWithFormat("unexpected response to '%s': '%s'", packet, response.GetStringRef().c_str());
    }
    else
    {
        error.SetErrorStringWithFormat("failed to sent packet: '%s'", packet);
    }
    return 0;
}

size_t
ProcessGDBRemote::DoWriteMemory (addr_t addr, const void *buf, size_t size, Error &error)
{
    StreamString packet;
    packet.Printf("M%llx,%zx:", addr, size);
    packet.PutBytesAsRawHex8(buf, size, eByteOrderHost, eByteOrderHost);
    StringExtractorGDBRemote response;
    if (m_gdb_comm.SendPacketAndWaitForResponse(packet.GetData(), packet.GetSize(), response, 2, true))
    {
        if (response.IsOKPacket())
        {
            error.Clear();
            return size;
        }
        else if (response.IsErrorPacket())
            error.SetErrorStringWithFormat("gdb remote returned an error: %s", response.GetStringRef().c_str());
        else if (response.IsUnsupportedPacket())
            error.SetErrorStringWithFormat("'%s' packet unsupported", packet.GetString().c_str());
        else
            error.SetErrorStringWithFormat("unexpected response to '%s': '%s'", packet.GetString().c_str(), response.GetStringRef().c_str());
    }
    else
    {
        error.SetErrorStringWithFormat("failed to sent packet: '%s'", packet.GetString().c_str());
    }
    return 0;
}

lldb::addr_t
ProcessGDBRemote::DoAllocateMemory (size_t size, uint32_t permissions, Error &error)
{
    addr_t allocated_addr = m_gdb_comm.AllocateMemory (size, permissions, m_packet_timeout);
    if (allocated_addr == LLDB_INVALID_ADDRESS)
        error.SetErrorStringWithFormat("unable to allocate %zu bytes of memory with permissions %u", size, permissions);
    else
        error.Clear();
    return allocated_addr;
}

Error
ProcessGDBRemote::DoDeallocateMemory (lldb::addr_t addr)
{
    Error error; 
    if (!m_gdb_comm.DeallocateMemory (addr, m_packet_timeout))
        error.SetErrorStringWithFormat("unable to deallocate memory at 0x%llx", addr);
    return error;
}


//------------------------------------------------------------------
// Process STDIO
//------------------------------------------------------------------

size_t
ProcessGDBRemote::GetSTDOUT (char *buf, size_t buf_size, Error &error)
{
    Mutex::Locker locker(m_stdio_mutex);
    size_t bytes_available = m_stdout_data.size();
    if (bytes_available > 0)
    {
        ProcessGDBRemoteLog::LogIf (GDBR_LOG_PROCESS, "ProcessGDBRemote::%s (&%p[%u]) ...", __FUNCTION__, buf, buf_size);
        if (bytes_available > buf_size)
        {
            memcpy(buf, m_stdout_data.data(), buf_size);
            m_stdout_data.erase(0, buf_size);
            bytes_available = buf_size;
        }
        else
        {
            memcpy(buf, m_stdout_data.data(), bytes_available);
            m_stdout_data.clear();

            //ResetEventBits(eBroadcastBitSTDOUT);
        }
    }
    return bytes_available;
}

size_t
ProcessGDBRemote::GetSTDERR (char *buf, size_t buf_size, Error &error)
{
    // Can we get STDERR through the remote protocol?
    return 0;
}

size_t
ProcessGDBRemote::PutSTDIN (const char *src, size_t src_len, Error &error)
{
    if (m_stdio_communication.IsConnected())
    {
        ConnectionStatus status;
        m_stdio_communication.Write(src, src_len, status, NULL);
    }
    return 0;
}

Error
ProcessGDBRemote::EnableBreakpoint (BreakpointSite *bp_site)
{
    Error error;
    assert (bp_site != NULL);

    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_BREAKPOINTS);
    user_id_t site_id = bp_site->GetID();
    const addr_t addr = bp_site->GetLoadAddress();
    if (log)
        log->Printf ("ProcessGDBRemote::EnableBreakpoint (size_id = %d) address = 0x%llx", site_id, (uint64_t)addr);

    if (bp_site->IsEnabled())
    {
        if (log)
            log->Printf ("ProcessGDBRemote::EnableBreakpoint (size_id = %d) address = 0x%llx -- SUCCESS (already enabled)", site_id, (uint64_t)addr);
        return error;
    }
    else
    {
        const size_t bp_op_size = GetSoftwareBreakpointTrapOpcode (bp_site);

        if (bp_site->HardwarePreferred())
        {
            // Try and set hardware breakpoint, and if that fails, fall through
            // and set a software breakpoint?
        }

        if (m_z0_supported)
        {
            char packet[64];
            const int packet_len = ::snprintf (packet, sizeof(packet), "Z0,%llx,%zx", addr, bp_op_size);
            assert (packet_len + 1 < sizeof(packet));
            StringExtractorGDBRemote response;
            if (m_gdb_comm.SendPacketAndWaitForResponse(packet, packet_len, response, 2, true))
            {
                if (response.IsUnsupportedPacket())
                {
                    // Disable z packet support and try again
                    m_z0_supported = 0;
                    return EnableBreakpoint (bp_site);
                }
                else if (response.IsOKPacket())
                {
                    bp_site->SetEnabled(true);
                    bp_site->SetType (BreakpointSite::eExternal);
                    return error;
                }
                else
                {
                    uint8_t error_byte = response.GetError();
                    if (error_byte)
                        error.SetErrorStringWithFormat("%x packet failed with error: %i (0x%2.2x).\n", packet, error_byte, error_byte);
                }
            }
        }
        else
        {
            return EnableSoftwareBreakpoint (bp_site);
        }
    }

    if (log)
    {
        const char *err_string = error.AsCString();
        log->Printf ("ProcessGDBRemote::EnableBreakpoint() error for breakpoint at 0x%8.8llx: %s",
                     bp_site->GetLoadAddress(),
                     err_string ? err_string : "NULL");
    }
    // We shouldn't reach here on a successful breakpoint enable...
    if (error.Success())
        error.SetErrorToGenericError();
    return error;
}

Error
ProcessGDBRemote::DisableBreakpoint (BreakpointSite *bp_site)
{
    Error error;
    assert (bp_site != NULL);
    addr_t addr = bp_site->GetLoadAddress();
    user_id_t site_id = bp_site->GetID();
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_BREAKPOINTS);
    if (log)
        log->Printf ("ProcessGDBRemote::DisableBreakpoint (site_id = %d) addr = 0x%8.8llx", site_id, (uint64_t)addr);

    if (bp_site->IsEnabled())
    {
        const size_t bp_op_size = GetSoftwareBreakpointTrapOpcode (bp_site);

        if (bp_site->IsHardware())
        {
            // TODO: disable hardware breakpoint...
        }
        else
        {
            if (m_z0_supported)
            {
                char packet[64];
                const int packet_len = ::snprintf (packet, sizeof(packet), "z0,%llx,%zx", addr, bp_op_size);
                assert (packet_len + 1 < sizeof(packet));
                StringExtractorGDBRemote response;
                if (m_gdb_comm.SendPacketAndWaitForResponse(packet, packet_len, response, 2, true))
                {
                    if (response.IsUnsupportedPacket())
                    {
                        error.SetErrorString("Breakpoint site was set with Z packet, yet remote debugserver states z packets are not supported.");
                    }
                    else if (response.IsOKPacket())
                    {
                        if (log)
                            log->Printf ("ProcessGDBRemote::DisableBreakpoint (site_id = %d) addr = 0x%8.8llx -- SUCCESS", site_id, (uint64_t)addr);
                        bp_site->SetEnabled(false);
                        return error;
                    }
                    else
                    {
                        uint8_t error_byte = response.GetError();
                        if (error_byte)
                            error.SetErrorStringWithFormat("%x packet failed with error: %i (0x%2.2x).\n", packet, error_byte, error_byte);
                    }
                }
            }
            else
            {
                return DisableSoftwareBreakpoint (bp_site);
            }
        }
    }
    else
    {
        if (log)
            log->Printf ("ProcessGDBRemote::DisableBreakpoint (site_id = %d) addr = 0x%8.8llx -- SUCCESS (already disabled)", site_id, (uint64_t)addr);
        return error;
    }

    if (error.Success())
        error.SetErrorToGenericError();
    return error;
}

Error
ProcessGDBRemote::EnableWatchpoint (WatchpointLocation *wp)
{
    Error error;
    if (wp)
    {
        user_id_t watchID = wp->GetID();
        addr_t addr = wp->GetLoadAddress();
        Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_WATCHPOINTS);
        if (log)
            log->Printf ("ProcessGDBRemote::EnableWatchpoint(watchID = %d)", watchID);
        if (wp->IsEnabled())
        {
            if (log)
                log->Printf("ProcessGDBRemote::EnableWatchpoint(watchID = %d) addr = 0x%8.8llx: watchpoint already enabled.", watchID, (uint64_t)addr);
            return error;
        }
        else
        {
            // Pass down an appropriate z/Z packet...
            error.SetErrorString("watchpoints not supported");
        }
    }
    else
    {
        error.SetErrorString("Watchpoint location argument was NULL.");
    }
    if (error.Success())
        error.SetErrorToGenericError();
    return error;
}

Error
ProcessGDBRemote::DisableWatchpoint (WatchpointLocation *wp)
{
    Error error;
    if (wp)
    {
        user_id_t watchID = wp->GetID();

        Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_WATCHPOINTS);

        addr_t addr = wp->GetLoadAddress();
        if (log)
            log->Printf ("ProcessGDBRemote::DisableWatchpoint (watchID = %d) addr = 0x%8.8llx", watchID, (uint64_t)addr);

        if (wp->IsHardware())
        {
            // Pass down an appropriate z/Z packet...
            error.SetErrorString("watchpoints not supported");
        }
        // TODO: clear software watchpoints if we implement them
    }
    else
    {
        error.SetErrorString("Watchpoint location argument was NULL.");
    }
    if (error.Success())
        error.SetErrorToGenericError();
    return error;
}

void
ProcessGDBRemote::Clear()
{
    m_flags = 0;
    m_thread_list.Clear();
    {
        Mutex::Locker locker(m_stdio_mutex);
        m_stdout_data.clear();
    }
    DestoryLibUnwindAddressSpace();
}

Error
ProcessGDBRemote::DoSignal (int signo)
{
    Error error;
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_PROCESS);
    if (log)
        log->Printf ("ProcessGDBRemote::DoSignal (signal = %d)", signo);

    if (!m_gdb_comm.SendAsyncSignal (signo))
        error.SetErrorStringWithFormat("failed to send signal %i", signo);
    return error;
}


Error
ProcessGDBRemote::DoDetach()
{
    Error error;
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_PROCESS);
    if (log)
        log->Printf ("ProcessGDBRemote::DoDetach()");

    //    if (DoSIGSTOP (true))
    //    {
    //        CloseChildFileDescriptors ();
    //
    //        // Scope for "locker" so we can reply to all of our exceptions (the SIGSTOP
    //        // exception).
    //        {
    //            Mutex::Locker locker(m_exception_messages_mutex);
    //            ReplyToAllExceptions();
    //        }
    //
    //        // Shut down the exception thread and cleanup our exception remappings
    //        Task().ShutDownExceptionThread();
    //
    //        pid_t pid = GetID();
    //
    //        // Detach from our process while we are stopped.
    //        errno = 0;
    //
    //        // Detach from our process
    //        ::ptrace (PT_DETACH, pid, (caddr_t)1, 0);
    //
    //        error.SetErrorToErrno();
    //
    //        if (log || error.Fail())
    //            error.PutToLog(log, "::ptrace (PT_DETACH, %u, (caddr_t)1, 0)", pid);
    //
    //        // Resume our task
    //        Task().Resume();
    //
    //        // NULL our task out as we have already retored all exception ports
    //        Task().Clear();
    //
    //        // Clear out any notion of the process we once were
    //        Clear();
    //
    //        SetPrivateState (eStateDetached);
    //        return true;
    //    }
    return error;
}

void
ProcessGDBRemote::STDIOReadThreadBytesReceived (void *baton, const void *src, size_t src_len)
{
    ProcessGDBRemote *process = (ProcessGDBRemote *)baton;
    process->AppendSTDOUT(static_cast<const char *>(src), src_len);
}

void
ProcessGDBRemote::AppendSTDOUT (const char* s, size_t len)
{
    ProcessGDBRemoteLog::LogIf (GDBR_LOG_PROCESS, "ProcessGDBRemote::%s (<%d> %s) ...", __FUNCTION__, len, s);
    Mutex::Locker locker(m_stdio_mutex);
    m_stdout_data.append(s, len);

    // FIXME: Make a real data object for this and put it out.
    BroadcastEventIfUnique (eBroadcastBitSTDOUT);
}


Error
ProcessGDBRemote::StartDebugserverProcess
(
    const char *debugserver_url,    // The connection string to use in the spawned debugserver ("localhost:1234" or "/dev/tty...")
    char const *inferior_argv[],    // Arguments for the inferior program including the path to the inferior itself as the first argument
    char const *inferior_envp[],    // Environment to pass along to the inferior program
    char const *stdio_path,
    lldb::pid_t attach_pid,         // If inferior inferior_argv == NULL, and attach_pid != LLDB_INVALID_PROCESS_ID then attach to this attach_pid
    const char *attach_name,        // Wait for the next process to launch whose basename matches "attach_name"
    bool wait_for_launch,           // Wait for the process named "attach_name" to launch
    ArchSpec& inferior_arch         // The arch of the inferior that we will launch
)
{
    Error error;
    if (m_debugserver_pid == LLDB_INVALID_PROCESS_ID)
    {
        // If we locate debugserver, keep that located version around
        static FileSpec g_debugserver_file_spec;

        FileSpec debugserver_file_spec;
        char debugserver_path[PATH_MAX];

        // Always check to see if we have an environment override for the path
        // to the debugserver to use and use it if we do.
        const char *env_debugserver_path = getenv("LLDB_DEBUGSERVER_PATH");
        if (env_debugserver_path)
            debugserver_file_spec.SetFile (env_debugserver_path);
        else
            debugserver_file_spec = g_debugserver_file_spec;
        bool debugserver_exists = debugserver_file_spec.Exists();
        if (!debugserver_exists)
        {
            // The debugserver binary is in the LLDB.framework/Resources
            // directory. 
            FileSpec framework_file_spec (Host::GetModuleFileSpecForHostAddress ((void *)lldb_private::Initialize));
            const char *framework_dir = framework_file_spec.GetDirectory().AsCString();
            const char *lldb_framework = ::strstr (framework_dir, "/LLDB.framework");

            if (lldb_framework)
            {
                int len = lldb_framework - framework_dir + strlen ("/LLDB.framework");
                ::snprintf (debugserver_path,
                            sizeof(debugserver_path),
                            "%.*s/Resources/%s",
                            len,
                            framework_dir,
                            DEBUGSERVER_BASENAME);
                debugserver_file_spec.SetFile (debugserver_path);
                debugserver_exists = debugserver_file_spec.Exists();
            }

            if (debugserver_exists)
            {
                g_debugserver_file_spec = debugserver_file_spec;
            }
            else
            {
                g_debugserver_file_spec.Clear();
                debugserver_file_spec.Clear();
            }
        }

        if (debugserver_exists)
        {
            debugserver_file_spec.GetPath (debugserver_path, sizeof(debugserver_path));

            m_stdio_communication.Clear();
            posix_spawnattr_t attr;

            Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet (GDBR_LOG_PROCESS);

            Error local_err;    // Errors that don't affect the spawning.
            if (log)
                log->Printf ("%s ( path='%s', argv=%p, envp=%p, arch=%s )", __FUNCTION__, debugserver_path, inferior_argv, inferior_envp, inferior_arch.AsCString());
            error.SetError( ::posix_spawnattr_init (&attr), eErrorTypePOSIX);
            if (error.Fail() || log)
                error.PutToLog(log, "::posix_spawnattr_init ( &attr )");
            if (error.Fail())
                return error;;

#if !defined (__arm__)

            // We don't need to do this for ARM, and we really shouldn't now that we
            // have multiple CPU subtypes and no posix_spawnattr call that allows us
            // to set which CPU subtype to launch...
            if (inferior_arch.GetType() == eArchTypeMachO)
            {
                cpu_type_t cpu = inferior_arch.GetCPUType();
                if (cpu != 0 && cpu != UINT32_MAX && cpu != LLDB_INVALID_CPUTYPE)
                {
                    size_t ocount = 0;
                    error.SetError( ::posix_spawnattr_setbinpref_np (&attr, 1, &cpu, &ocount), eErrorTypePOSIX);
                    if (error.Fail() || log)
                        error.PutToLog(log, "::posix_spawnattr_setbinpref_np ( &attr, 1, cpu_type = 0x%8.8x, count => %zu )", cpu, ocount);

                    if (error.Fail() != 0 || ocount != 1)
                        return error;
                }
            }

#endif

            Args debugserver_args;
            char arg_cstr[PATH_MAX];
            bool launch_process = true;

            if (inferior_argv == NULL && attach_pid != LLDB_INVALID_PROCESS_ID)
                launch_process = false;
            else if (attach_name)
                launch_process = false; // Wait for a process whose basename matches that in inferior_argv[0]

            bool pass_stdio_path_to_debugserver = true;
            lldb_utility::PseudoTerminal pty;
            if (stdio_path == NULL)
            {
                pass_stdio_path_to_debugserver = false;
                if (pty.OpenFirstAvailableMaster(O_RDWR|O_NOCTTY, NULL, 0))
                {
                    struct termios stdin_termios;
                    if (::tcgetattr (pty.GetMasterFileDescriptor(), &stdin_termios) == 0)
                    {
                        stdin_termios.c_lflag &= ~ECHO;     // Turn off echoing
                        stdin_termios.c_lflag &= ~ICANON;   // Get one char at a time
                        ::tcsetattr (pty.GetMasterFileDescriptor(), TCSANOW, &stdin_termios);
                    }
                    stdio_path = pty.GetSlaveName (NULL, 0);
                }
            }

            // Start args with "debugserver /file/path -r --"
            debugserver_args.AppendArgument(debugserver_path);
            debugserver_args.AppendArgument(debugserver_url);
            debugserver_args.AppendArgument("--native-regs");   // use native registers, not the GDB registers
            debugserver_args.AppendArgument("--setsid");        // make debugserver run in its own session so
                                                        // signals generated by special terminal key
                                                        // sequences (^C) don't affect debugserver

            // Only set the inferior
            if (launch_process)
            {
                if (stdio_path && pass_stdio_path_to_debugserver)
                {
                    debugserver_args.AppendArgument("-s");    // short for --stdio-path
                    StreamString strm;
                    strm.Printf("'%s'", stdio_path);
                    debugserver_args.AppendArgument(strm.GetData());    // path to file to have inferior open as it's STDIO
                }
            }

            const char *env_debugserver_log_file = getenv("LLDB_DEBUGSERVER_LOG_FILE");
            if (env_debugserver_log_file)
            {
                ::snprintf (arg_cstr, sizeof(arg_cstr), "--log-file=%s", env_debugserver_log_file);
                debugserver_args.AppendArgument(arg_cstr);
            }

            const char *env_debugserver_log_flags = getenv("LLDB_DEBUGSERVER_LOG_FLAGS");
            if (env_debugserver_log_flags)
            {
                ::snprintf (arg_cstr, sizeof(arg_cstr), "--log-flags=%s", env_debugserver_log_flags);
                debugserver_args.AppendArgument(arg_cstr);
            }
//            debugserver_args.AppendArgument("--log-file=/tmp/debugserver.txt");
//            debugserver_args.AppendArgument("--log-flags=0x800e0e");

            // Now append the program arguments
            if (launch_process)
            {
                if (inferior_argv)
                {
                    // Terminate the debugserver args so we can now append the inferior args
                    debugserver_args.AppendArgument("--");

                    for (int i = 0; inferior_argv[i] != NULL; ++i)
                        debugserver_args.AppendArgument (inferior_argv[i]);
                }
                else
                {
                    // Will send environment entries with the 'QEnvironment:' packet
                    // Will send arguments with the 'A' packet
                }
            }
            else if (attach_pid != LLDB_INVALID_PROCESS_ID)
            {
                ::snprintf (arg_cstr, sizeof(arg_cstr), "--attach=%u", attach_pid);
                debugserver_args.AppendArgument (arg_cstr);
            }
            else if (attach_name && attach_name[0])
            {
                if (wait_for_launch)
                    debugserver_args.AppendArgument ("--waitfor");
                else
                    debugserver_args.AppendArgument ("--attach");
                debugserver_args.AppendArgument (attach_name);
            }

            Error file_actions_err;
            posix_spawn_file_actions_t file_actions;
#if DONT_CLOSE_DEBUGSERVER_STDIO
            file_actions_err.SetErrorString ("Remove this after uncommenting the code block below.");
#else
            file_actions_err.SetError( ::posix_spawn_file_actions_init (&file_actions), eErrorTypePOSIX);
            if (file_actions_err.Success())
            {
                ::posix_spawn_file_actions_addclose (&file_actions, STDIN_FILENO);
                ::posix_spawn_file_actions_addclose (&file_actions, STDOUT_FILENO);
                ::posix_spawn_file_actions_addclose (&file_actions, STDERR_FILENO);
            }
#endif

            if (log)
            {
                StreamString strm;
                debugserver_args.Dump (&strm);
                log->Printf("%s arguments:\n%s", debugserver_args.GetArgumentAtIndex(0), strm.GetData());
            }

            error.SetError(::posix_spawnp (&m_debugserver_pid,
                                             debugserver_path,
                                             file_actions_err.Success() ? &file_actions : NULL,
                                             &attr,
                                             debugserver_args.GetArgumentVector(),
                                             (char * const*)inferior_envp),
                             eErrorTypePOSIX);

            if (file_actions_err.Success())
                ::posix_spawn_file_actions_destroy (&file_actions);

            // We have seen some cases where posix_spawnp was returning a valid
            // looking pid even when an error was returned, so clear it out
            if (error.Fail())
                m_debugserver_pid = LLDB_INVALID_PROCESS_ID;

            if (error.Fail() || log)
                error.PutToLog(log, "::posix_spawnp ( pid => %i, path = '%s', file_actions = %p, attr = %p, argv = %p, envp = %p )", m_debugserver_pid, debugserver_path, NULL, &attr, inferior_argv, inferior_envp);

//            if (m_debugserver_pid != LLDB_INVALID_PROCESS_ID)
//            {
//                std::auto_ptr<ConnectionFileDescriptor> conn_ap(new ConnectionFileDescriptor (pty.ReleaseMasterFileDescriptor(), true));
//                if (conn_ap.get())
//                {
//                    m_stdio_communication.SetConnection(conn_ap.release());
//                    if (m_stdio_communication.IsConnected())
//                    {
//                        m_stdio_communication.SetReadThreadBytesReceivedCallback (STDIOReadThreadBytesReceived, this);
//                        m_stdio_communication.StartReadThread();
//                    }
//                }
//            }
        }
        else
        {
            error.SetErrorStringWithFormat ("Unable to locate " DEBUGSERVER_BASENAME ".\n");
        }

        if (m_debugserver_pid != LLDB_INVALID_PROCESS_ID)
            StartAsyncThread ();
    }
    return error;
}

bool
ProcessGDBRemote::MonitorDebugserverProcess
(
    void *callback_baton,
    lldb::pid_t debugserver_pid,
    int signo,          // Zero for no signal
    int exit_status     // Exit value of process if signal is zero
)
{
    // We pass in the ProcessGDBRemote inferior process it and name it
    // "gdb_remote_pid". The process ID is passed in the "callback_baton"
    // pointer value itself, thus we need the double cast...

    // "debugserver_pid" argument passed in is the process ID for
    // debugserver that we are tracking...

    lldb::pid_t gdb_remote_pid = (lldb::pid_t)(intptr_t)callback_baton;
    TargetSP target_sp(Debugger::GetSharedInstance().GetTargetList().FindTargetWithProcessID (gdb_remote_pid));
    if (target_sp)
    {
        ProcessSP process_sp (target_sp->GetProcessSP());
        if (process_sp)
        {
            // Sleep for a half a second to make sure our inferior process has
            // time to set its exit status before we set it incorrectly when
            // both the debugserver and the inferior process shut down.
            usleep (500000);
            // If our process hasn't yet exited, debugserver might have died.
            // If the process did exit, the we are reaping it.
            if (process_sp->GetState() != eStateExited)
            {
                char error_str[1024];
                if (signo)
                {
                    const char *signal_cstr = process_sp->GetUnixSignals().GetSignalAsCString (signo);
                    if (signal_cstr)
                        ::snprintf (error_str, sizeof (error_str), DEBUGSERVER_BASENAME " died with signal %s", signal_cstr);
                    else
                        ::snprintf (error_str, sizeof (error_str), DEBUGSERVER_BASENAME " died with signal %i", signo);
                }
                else
                {
                    ::snprintf (error_str, sizeof (error_str), DEBUGSERVER_BASENAME " died with an exit status of 0x%8.8x", exit_status);
                }

                process_sp->SetExitStatus (-1, error_str);
            }
            else
            {
                ProcessGDBRemote *gdb_process = (ProcessGDBRemote *)process_sp.get();
                // Debugserver has exited we need to let our ProcessGDBRemote
                // know that it no longer has a debugserver instance
                gdb_process->m_debugserver_pid = LLDB_INVALID_PROCESS_ID;
                // We are returning true to this function below, so we can
                // forget about the monitor handle.
                gdb_process->m_debugserver_monitor = 0;
            }
        }
    }
    return true;
}

void
ProcessGDBRemote::KillDebugserverProcess ()
{
    if (m_debugserver_pid != LLDB_INVALID_PROCESS_ID)
    {
        ::kill (m_debugserver_pid, SIGINT);
        m_debugserver_pid = LLDB_INVALID_PROCESS_ID;
    }
}

void
ProcessGDBRemote::Initialize()
{
    static bool g_initialized = false;

    if (g_initialized == false)
    {
        g_initialized = true;
        PluginManager::RegisterPlugin (GetPluginNameStatic(),
                                       GetPluginDescriptionStatic(),
                                       CreateInstance);

        Log::Callbacks log_callbacks = {
            ProcessGDBRemoteLog::DisableLog,
            ProcessGDBRemoteLog::EnableLog,
            ProcessGDBRemoteLog::ListLogCategories
        };

        Log::RegisterLogChannel (ProcessGDBRemote::GetPluginNameStatic(), log_callbacks);
    }
}

bool
ProcessGDBRemote::SetCurrentGDBRemoteThread (int tid)
{
    if (m_curr_tid == tid)
        return true;

    char packet[32];
    const int packet_len = ::snprintf (packet, sizeof(packet), "Hg%x", tid);
    assert (packet_len + 1 < sizeof(packet));
    StringExtractorGDBRemote response;
    if (m_gdb_comm.SendPacketAndWaitForResponse(packet, packet_len, response, 2, false))
    {
        if (response.IsOKPacket())
        {
            m_curr_tid = tid;
            return true;
        }
    }
    return false;
}

bool
ProcessGDBRemote::SetCurrentGDBRemoteThreadForRun (int tid)
{
    if (m_curr_tid_run == tid)
        return true;

    char packet[32];
    const int packet_len = ::snprintf (packet, sizeof(packet), "Hg%x", tid);
    assert (packet_len + 1 < sizeof(packet));
    StringExtractorGDBRemote response;
    if (m_gdb_comm.SendPacketAndWaitForResponse(packet, packet_len, response, 2, false))
    {
        if (response.IsOKPacket())
        {
            m_curr_tid_run = tid;
            return true;
        }
    }
    return false;
}

void
ProcessGDBRemote::ResetGDBRemoteState ()
{
    // Reset and GDB remote state
    m_curr_tid = LLDB_INVALID_THREAD_ID;
    m_curr_tid_run = LLDB_INVALID_THREAD_ID;
    m_z0_supported = 1;
}


bool
ProcessGDBRemote::StartAsyncThread ()
{
    ResetGDBRemoteState ();

    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_PROCESS);

    if (log)
        log->Printf ("ProcessGDBRemote::%s ()", __FUNCTION__);

    // Create a thread that watches our internal state and controls which
    // events make it to clients (into the DCProcess event queue).
    m_async_thread = Host::ThreadCreate ("<lldb.process.gdb-remote.async>", ProcessGDBRemote::AsyncThread, this, NULL);
    return m_async_thread != LLDB_INVALID_HOST_THREAD;
}

void
ProcessGDBRemote::StopAsyncThread ()
{
    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet(GDBR_LOG_PROCESS);

    if (log)
        log->Printf ("ProcessGDBRemote::%s ()", __FUNCTION__);

    m_async_broadcaster.BroadcastEvent (eBroadcastBitAsyncThreadShouldExit);

    // Stop the stdio thread
    if (m_async_thread != LLDB_INVALID_HOST_THREAD)
    {
        Host::ThreadJoin (m_async_thread, NULL, NULL);
    }
}


void *
ProcessGDBRemote::AsyncThread (void *arg)
{
    ProcessGDBRemote *process = (ProcessGDBRemote*) arg;

    Log *log = ProcessGDBRemoteLog::GetLogIfAllCategoriesSet (GDBR_LOG_PROCESS);
    if (log)
        log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) thread starting...", __FUNCTION__, arg, process->GetID());

    Listener listener ("ProcessGDBRemote::AsyncThread");
    EventSP event_sp;
    const uint32_t desired_event_mask = eBroadcastBitAsyncContinue |
                                        eBroadcastBitAsyncThreadShouldExit;

    if (listener.StartListeningForEvents (&process->m_async_broadcaster, desired_event_mask) == desired_event_mask)
    {
        bool done = false;
        while (!done)
        {
            if (log)
                log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) listener.WaitForEvent (NULL, event_sp)...", __FUNCTION__, arg, process->GetID());
            if (listener.WaitForEvent (NULL, event_sp))
            {
                const uint32_t event_type = event_sp->GetType();
                switch (event_type)
                {
                    case eBroadcastBitAsyncContinue:
                        {
                            const EventDataBytes *continue_packet = EventDataBytes::GetEventDataFromEvent(event_sp.get());

                            if (continue_packet)
                            {
                                const char *continue_cstr = (const char *)continue_packet->GetBytes ();
                                const size_t continue_cstr_len = continue_packet->GetByteSize ();
                                if (log)
                                    log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) got eBroadcastBitAsyncContinue: %s", __FUNCTION__, arg, process->GetID(), continue_cstr);

                                process->SetPrivateState(eStateRunning);
                                StringExtractorGDBRemote response;
                                StateType stop_state = process->GetGDBRemote().SendContinuePacketAndWaitForResponse (process, continue_cstr, continue_cstr_len, response);

                                switch (stop_state)
                                {
                                case eStateStopped:
                                case eStateCrashed:
                                case eStateSuspended:
                                    process->m_last_stop_packet = response;
                                    process->m_last_stop_packet.SetFilePos (0);
                                    process->SetPrivateState (stop_state);
                                    break;

                                case eStateExited:
                                    process->m_last_stop_packet = response;
                                    process->m_last_stop_packet.SetFilePos (0);
                                    response.SetFilePos(1);
                                    process->SetExitStatus(response.GetHexU8(), NULL);
                                    done = true;
                                    break;

                                case eStateInvalid:
                                    break;

                                default:
                                    process->SetPrivateState (stop_state);
                                    break;
                                }
                            }
                        }
                        break;

                    case eBroadcastBitAsyncThreadShouldExit:
                        if (log)
                            log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) got eBroadcastBitAsyncThreadShouldExit...", __FUNCTION__, arg, process->GetID());
                        done = true;
                        break;

                    default:
                        if (log)
                            log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) got unknown event 0x%8.8x", __FUNCTION__, arg, process->GetID(), event_type);
                        done = true;
                        break;
                }
            }
            else
            {
                if (log)
                    log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) listener.WaitForEvent (NULL, event_sp) => false", __FUNCTION__, arg, process->GetID());
                done = true;
            }
        }
    }

    if (log)
        log->Printf ("ProcessGDBRemote::%s (arg = %p, pid = %i) thread exiting...", __FUNCTION__, arg, process->GetID());

    process->m_async_thread = LLDB_INVALID_HOST_THREAD;
    return NULL;
}

lldb_private::unw_addr_space_t
ProcessGDBRemote::GetLibUnwindAddressSpace ()
{
    unw_targettype_t target_type = UNW_TARGET_UNSPECIFIED;

    ArchSpec::CPU arch_cpu = m_target.GetArchitecture().GetGenericCPUType();
    if (arch_cpu == ArchSpec::eCPU_i386)
        target_type = UNW_TARGET_I386;
    else if (arch_cpu == ArchSpec::eCPU_x86_64)
        target_type = UNW_TARGET_X86_64;

    if (m_libunwind_addr_space)
    {
        if (m_libunwind_target_type != target_type)
            DestoryLibUnwindAddressSpace();
        else
            return m_libunwind_addr_space;
    }
    unw_accessors_t callbacks = get_macosx_libunwind_callbacks ();
    m_libunwind_addr_space = unw_create_addr_space (&callbacks, target_type);
    if (m_libunwind_addr_space)
        m_libunwind_target_type = target_type;
    else
        m_libunwind_target_type = UNW_TARGET_UNSPECIFIED;
    return m_libunwind_addr_space;
}

void
ProcessGDBRemote::DestoryLibUnwindAddressSpace ()
{
    if (m_libunwind_addr_space)
    {
        unw_destroy_addr_space (m_libunwind_addr_space);
        m_libunwind_addr_space = NULL;
    }
    m_libunwind_target_type = UNW_TARGET_UNSPECIFIED;
}


const char *
ProcessGDBRemote::GetDispatchQueueNameForThread
(
    addr_t thread_dispatch_qaddr,
    std::string &dispatch_queue_name
)
{
    dispatch_queue_name.clear();
    if (thread_dispatch_qaddr != 0 && thread_dispatch_qaddr != LLDB_INVALID_ADDRESS)
    {
        // Cache the dispatch_queue_offsets_addr value so we don't always have
        // to look it up
        if (m_dispatch_queue_offsets_addr == LLDB_INVALID_ADDRESS)
        {
            ModuleSP module_sp(GetTarget().GetImages().FindFirstModuleForFileSpec (FileSpec("libSystem.B.dylib")));
            if (module_sp.get() == NULL)
                return NULL;

            const Symbol *dispatch_queue_offsets_symbol = module_sp->FindFirstSymbolWithNameAndType (ConstString("dispatch_queue_offsets"), eSymbolTypeData);
            if (dispatch_queue_offsets_symbol)
                m_dispatch_queue_offsets_addr = dispatch_queue_offsets_symbol->GetValue().GetLoadAddress(this);

            if (m_dispatch_queue_offsets_addr == LLDB_INVALID_ADDRESS)
                return NULL;
        }

        uint8_t memory_buffer[8];
        DataExtractor data(memory_buffer, sizeof(memory_buffer), GetByteOrder(), GetAddressByteSize());

        // Excerpt from src/queue_private.h
        struct dispatch_queue_offsets_s
        {
            uint16_t dqo_version;
            uint16_t dqo_label;
            uint16_t dqo_label_size;
        } dispatch_queue_offsets;


        Error error;
        if (ReadMemory (m_dispatch_queue_offsets_addr, memory_buffer, sizeof(dispatch_queue_offsets), error) == sizeof(dispatch_queue_offsets))
        {
            uint32_t data_offset = 0;
            if (data.GetU16(&data_offset, &dispatch_queue_offsets.dqo_version, sizeof(dispatch_queue_offsets)/sizeof(uint16_t)))
            {
                if (ReadMemory (thread_dispatch_qaddr, &memory_buffer, data.GetAddressByteSize(), error) == data.GetAddressByteSize())
                {
                    data_offset = 0;
                    lldb::addr_t queue_addr = data.GetAddress(&data_offset);
                    lldb::addr_t label_addr = queue_addr + dispatch_queue_offsets.dqo_label;
                    dispatch_queue_name.resize(dispatch_queue_offsets.dqo_label_size, '\0');
                    size_t bytes_read = ReadMemory (label_addr, &dispatch_queue_name[0], dispatch_queue_offsets.dqo_label_size, error);
                    if (bytes_read < dispatch_queue_offsets.dqo_label_size)
                        dispatch_queue_name.erase (bytes_read);
                }
            }
        }
    }
    if (dispatch_queue_name.empty())
        return NULL;
    return dispatch_queue_name.c_str();
}

