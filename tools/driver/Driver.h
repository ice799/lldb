//===-- Driver.h ------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef lldb_Driver_h_
#define lldb_Driver_h_

#include "lldb/Utility/PseudoTerminal.h"

#include <set>
#include <bitset>
#include <string>
#include <vector>

#include "lldb/API/SBDefines.h"
#include "lldb/API/SBBroadcaster.h"
#include "lldb/API/SBDebugger.h"
#include "lldb/API/SBError.h"
#include "lldb/API/SBInputReader.h"


class IOChannel;

namespace lldb
{
    class SBInputReader;
}


class Driver : public lldb::SBBroadcaster
{
public:
    enum {
        eBroadcastBitReadyForInput    = (1 << 0),
        eBroadcastBitThreadShouldExit = (1 << 1)
    };

    Driver ();

    virtual
    ~Driver ();

    void
    MainLoop ();

    void
    PutSTDIN (const char *src, size_t src_len);

    void
    GetFromMaster (const char *src, size_t src_len);

    bool
    HandleIOEvent (const lldb::SBEvent &event);

    void
    HandleProcessEvent (const lldb::SBEvent &event);

    lldb::SBError
    ParseArgs (int argc, const char *argv[], FILE *out_fh, bool &do_exit);

    const char *
    GetFilename() const;

    const char *
    GetCrashLogFilename() const;

    const char *
    GetArchName() const;

    lldb::ScriptLanguage
    GetScriptLanguage() const;

    size_t
    GetNumSourceCommandFiles () const;

    const char *
    GetSourceCommandFileAtIndex (uint32_t idx) const;

    bool
    GetDebugMode() const;


    class OptionData
    {
    public:
        OptionData ();
       ~OptionData ();

        void
        Clear();

        //static lldb::OptionDefinition m_cmd_option_table[];

        std::string m_filename;
        lldb::ScriptLanguage m_script_lang;
        std::string m_crash_log;
        std::vector<std::string> m_source_command_files;
        bool m_debug_mode;
        bool m_print_version;
        bool m_print_help;
        typedef std::set<char> OptionSet;
        OptionSet m_seen_options;
    };


    static lldb::SBError
    SetOptionValue (int option_idx,
                    const char *option_arg,
                    Driver::OptionData &data);


    lldb::SBDebugger &
    GetDebugger()
    {
        return m_debugger;
    }

private:
    lldb::SBDebugger m_debugger;
    lldb_utility::PseudoTerminal m_editline_pty;
    FILE *m_editline_slave_fh;
    lldb::SBInputReader m_editline_reader;
    std::auto_ptr<IOChannel> m_io_channel_ap;
    OptionData m_option_data;
    bool m_waiting_for_command;

    void
    ResetOptionValues ();

    void
    GetProcessSTDOUT ();

    void
    GetProcessSTDERR ();

    void
    UpdateCurrentThread ();

    void
    CloseIOChannelFile ();

    static size_t
    EditLineInputReaderCallback (void *baton, 
                                 lldb::SBInputReader *reader, 
                                 lldb::InputReaderAction notification,
                                 const char *bytes, 
                                 size_t bytes_len);

    static void
    ReadThreadBytesReceived (void *baton, const void *src, size_t src_len);

    static void
    MasterThreadBytesReceived (void *baton, const void *src, size_t src_len);
    
    void
    ReadyForCommand ();
};

#endif // lldb_Driver_h_
