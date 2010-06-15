//===-- CommandObjectLog.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CommandObjectLog.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private-log.h"

#include "lldb/Interpreter/Args.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/FileSpec.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/Module.h"
#include "lldb/Interpreter/Options.h"
#include "lldb/Core/RegularExpression.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/Timer.h"

#include "lldb/Interpreter/CommandContext.h"
#include "lldb/Interpreter/CommandReturnObject.h"

#include "lldb/Symbol/LineTable.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolFile.h"
#include "lldb/Symbol/SymbolVendor.h"

#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

using namespace lldb;
using namespace lldb_private;


static LogChannelSP
GetLogChannelPluginForChannel (const char *channel)
{
    std::string log_channel_plugin_name(channel);
    log_channel_plugin_name += LogChannel::GetPluginSuffix();
    LogChannelSP log_channel_sp (LogChannel::FindPlugin (log_channel_plugin_name.c_str()));
    return log_channel_sp;
}


class CommandObjectLogEnable : public CommandObject
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    CommandObjectLogEnable() :
        CommandObject ("log enable",
                       "Enable logging for a single log channel.",
                       "log enable [<cmd-options>] <channel>")
    {
    }

    virtual
    ~CommandObjectLogEnable()
    {
    }

    Options *
    GetOptions ()
    {
        return &m_options;
    }

    virtual bool
    Execute (Args& args,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        if (args.GetArgumentCount() < 1)
        {
            result.GetErrorStream() << m_cmd_syntax.c_str();
        }
        else
        {
            Log::Callbacks log_callbacks;

            std::string channel(args.GetArgumentAtIndex(0));
            args.Shift ();  // Shift off the channel
            StreamSP log_stream_sp;

            if (m_options.log_file.empty())
            {
                std::string log_file("<lldb.debugger>");
                LogStreamMap::iterator pos = m_log_streams.find(log_file);
                if (pos == m_log_streams.end())
                {
                    log_stream_sp = Log::GetStreamForSTDOUT ();
                    if (log_stream_sp)
                        m_log_streams[log_file] = log_stream_sp;
                }
                else
                    log_stream_sp = pos->second;
            }
            else
            {
                LogStreamMap::iterator pos = m_log_streams.find(m_options.log_file);
                if (pos == m_log_streams.end())
                {
                    log_stream_sp.reset (new StreamFile (m_options.log_file.c_str(), "w"));
                    m_log_streams[m_options.log_file] = log_stream_sp;
                }
                else
                    log_stream_sp = pos->second;
            }
            assert (log_stream_sp.get());
            uint32_t log_options = m_options.log_options;
            if (log_options == 0)
                log_options = LLDB_LOG_OPTION_PREPEND_THREAD_NAME | LLDB_LOG_OPTION_THREADSAFE;
            if (Log::GetLogChannelCallbacks (channel.c_str(), log_callbacks))
            {
                log_callbacks.enable (log_stream_sp, log_options, args, &result.GetErrorStream());
                result.SetStatus(eReturnStatusSuccessFinishNoResult);
            }
            else
            {
                LogChannelSP log_channel_sp (GetLogChannelPluginForChannel(channel.c_str()));
                if (log_channel_sp)
                {
                    if (log_channel_sp->Enable (log_stream_sp, log_options, &result.GetErrorStream(), args))
                    {
                        result.SetStatus (eReturnStatusSuccessFinishNoResult);
                    }
                    else
                    {
                        result.AppendErrorWithFormat("Invalid log channel '%s'.\n", channel.c_str());
                        result.SetStatus (eReturnStatusFailed);
                    }
                }
                else
                {
                    result.AppendErrorWithFormat("Invalid log channel '%s'.\n", channel.c_str());
                    result.SetStatus (eReturnStatusFailed);
                }
            }
        }
        return result.Succeeded();
    }


    class CommandOptions : public Options
    {
    public:

        CommandOptions () :
            Options (),
            log_file (),
            log_options (0)
        {
        }


        virtual
        ~CommandOptions ()
        {
        }

        virtual Error
        SetOptionValue (int option_idx, const char *option_arg)
        {
            Error error;
            char short_option = (char) m_getopt_table[option_idx].val;

            switch (short_option)
            {
            case 'f':  log_file = option_arg;                                 break;
            case 't':  log_options |= LLDB_LOG_OPTION_THREADSAFE;             break;
            case 'v':  log_options |= LLDB_LOG_OPTION_VERBOSE;                break;
            case 'g':  log_options |= LLDB_LOG_OPTION_DEBUG;                  break;
            case 's':  log_options |= LLDB_LOG_OPTION_PREPEND_SEQUENCE;       break;
            case 'T':  log_options |= LLDB_LOG_OPTION_PREPEND_TIMESTAMP;      break;
            case 'p':  log_options |= LLDB_LOG_OPTION_PREPEND_PROC_AND_THREAD;break;
            case 'n':  log_options |= LLDB_LOG_OPTION_PREPEND_THREAD_NAME;    break;
            default:
                error.SetErrorStringWithFormat ("Unrecognized option '%c'\n", short_option);
                break;
            }

            return error;
        }

        void
        ResetOptionValues ()
        {
            Options::ResetOptionValues();
            log_file.clear();
            log_options = 0;
        }

        const lldb::OptionDefinition*
        GetDefinitions ()
        {
            return g_option_table;
        }

        // Options table: Required for subclasses of Options.

        static lldb::OptionDefinition g_option_table[];

        // Instance variables to hold the values for command options.

        std::string log_file;
        uint32_t log_options;
    };

protected:
    typedef std::map<std::string, StreamSP> LogStreamMap;
    CommandOptions m_options;
    LogStreamMap m_log_streams;
};

lldb::OptionDefinition
CommandObjectLogEnable::CommandOptions::g_option_table[] =
{
{ LLDB_OPT_SET_1, false, "file",       'f', required_argument, NULL, 0, "<filename>",   "Set the destination file to log to."},
{ LLDB_OPT_SET_1, false, "threadsafe", 't', no_argument,       NULL, 0, NULL,           "Enable thread safe logging to avoid interweaved log lines." },
{ LLDB_OPT_SET_1, false, "verbose",    'v', no_argument,       NULL, 0, NULL,           "Enable verbose logging." },
{ LLDB_OPT_SET_1, false, "debug",      'g', no_argument,       NULL, 0, NULL,           "Enable debug logging." },
{ LLDB_OPT_SET_1, false, "sequence",   's', no_argument,       NULL, 0, NULL,           "Prepend all log lines with an increasing integer sequence id." },
{ LLDB_OPT_SET_1, false, "timestamp",  'T', no_argument,       NULL, 0, NULL,           "Prepend all log lines with a timestamp." },
{ LLDB_OPT_SET_1, false, "pid-tid",    'p', no_argument,       NULL, 0, NULL,           "Prepend all log lines with the process and thread ID that generates the log line." },
{ LLDB_OPT_SET_1, false, "thread-name",'n', no_argument,       NULL, 0, NULL,           "Prepend all log lines with the thread name for the thread that generates the log line." },
{ 0, false, NULL,          0,  0,                 NULL, 0, NULL,           NULL }
};

class CommandObjectLogDisable : public CommandObject
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    CommandObjectLogDisable() :
        CommandObject ("log disable",
                        "Disable one or more log channels.",
                        "log disable <channel> [<channel> ...]")
    {
    }

    virtual
    ~CommandObjectLogDisable()
    {
    }

    virtual bool
    Execute (Args& args,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        const size_t argc = args.GetArgumentCount();
        if (argc == 0)
        {
            result.GetErrorStream() << m_cmd_syntax.c_str();
        }
        else
        {
            for (size_t i=0; i<argc; ++i)
            {
                Log::Callbacks log_callbacks;

                std::string channel(args.GetArgumentAtIndex(i));
                if (Log::GetLogChannelCallbacks (channel.c_str(), log_callbacks))
                {
                    log_callbacks.disable ();
                    result.SetStatus(eReturnStatusSuccessFinishNoResult);
                }
                else if (channel == "all")
                {
                    Log::DisableAllLogChannels();
                }
                else
                {
                    LogChannelSP log_channel_sp (GetLogChannelPluginForChannel(channel.c_str()));
                    if (log_channel_sp)
                    {
                        log_channel_sp->Disable();
                        result.SetStatus(eReturnStatusSuccessFinishNoResult);
                    }
                    else
                        result.AppendErrorWithFormat("Invalid log channel '%s'.\n", args.GetArgumentAtIndex(0));
                }
            }
        }
        return result.Succeeded();
    }
};

class CommandObjectLogList : public CommandObject
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    CommandObjectLogList() :
        CommandObject ("log list",
                       "List the log categories for one or more log channels.",
                       "log list <channel> [<channel> ...]")
    {
    }

    virtual
    ~CommandObjectLogList()
    {
    }

    virtual bool
    Execute (Args& args,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        const size_t argc = args.GetArgumentCount();
        if (argc == 0)
        {
            Log::ListAllLogChannels (&result.GetOutputStream());
            result.SetStatus(eReturnStatusSuccessFinishResult);
        }
        else
        {
            for (size_t i=0; i<argc; ++i)
            {
                Log::Callbacks log_callbacks;

                std::string channel(args.GetArgumentAtIndex(i));
                if (Log::GetLogChannelCallbacks (channel.c_str(), log_callbacks))
                {
                    log_callbacks.list_categories (&result.GetOutputStream());
                    result.SetStatus(eReturnStatusSuccessFinishResult);
                }
                else if (channel == "all")
                {
                    Log::ListAllLogChannels (&result.GetOutputStream());
                    result.SetStatus(eReturnStatusSuccessFinishResult);
                }
                else
                {
                    LogChannelSP log_channel_sp (GetLogChannelPluginForChannel(channel.c_str()));
                    if (log_channel_sp)
                    {
                        log_channel_sp->ListCategories(&result.GetOutputStream());
                        result.SetStatus(eReturnStatusSuccessFinishNoResult);
                    }
                    else
                        result.AppendErrorWithFormat("Invalid log channel '%s'.\n", args.GetArgumentAtIndex(0));
                }
            }
        }
        return result.Succeeded();
    }
};

class CommandObjectLogTimer : public CommandObject
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    CommandObjectLogTimer() :
        CommandObject ("log timers",
                       "Enable, disable, dump, and reset LLDB internal performance timers.",
                       "log timers < enable | disable | dump | reset >")
    {
    }

    virtual
    ~CommandObjectLogTimer()
    {
    }

    virtual bool
    Execute (Args& args,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        const size_t argc = args.GetArgumentCount();
        result.SetStatus(eReturnStatusFailed);

        if (argc == 1)
        {
            const char *sub_command = args.GetArgumentAtIndex(0);

            if (strcasecmp(sub_command, "enable") == 0)
            {
                Timer::SetDisplayDepth (UINT32_MAX);
                result.SetStatus(eReturnStatusSuccessFinishNoResult);
            }
            else if (strcasecmp(sub_command, "disable") == 0)
            {
                Timer::DumpCategoryTimes (&result.GetOutputStream());
                Timer::SetDisplayDepth (0);
                result.SetStatus(eReturnStatusSuccessFinishResult);
            }
            else if (strcasecmp(sub_command, "dump") == 0)
            {
                Timer::DumpCategoryTimes (&result.GetOutputStream());
                result.SetStatus(eReturnStatusSuccessFinishResult);
            }
            else if (strcasecmp(sub_command, "reset") == 0)
            {
                Timer::ResetCategoryTimes ();
                result.SetStatus(eReturnStatusSuccessFinishResult);
            }

        }
        if (!result.Succeeded())
        {
            result.AppendError("Missing subcommand");
            result.AppendErrorWithFormat("Usage: %s\n", m_cmd_syntax.c_str());
        }
        return result.Succeeded();
    }
};

//----------------------------------------------------------------------
// CommandObjectLog constructor
//----------------------------------------------------------------------
CommandObjectLog::CommandObjectLog(CommandInterpreter *interpreter) :
    CommandObjectMultiword ("log",
                            "A set of commands for operating on logs.",
                            "log <command> [<command-options>]")
{
    LoadSubCommand (CommandObjectSP (new CommandObjectLogEnable), "enable", interpreter);
    LoadSubCommand (CommandObjectSP (new CommandObjectLogDisable), "disable", interpreter);
    LoadSubCommand (CommandObjectSP (new CommandObjectLogList), "list", interpreter);
    LoadSubCommand (CommandObjectSP (new CommandObjectLogTimer), "timers", interpreter);
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
CommandObjectLog::~CommandObjectLog()
{
}




