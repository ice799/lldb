//===-- Driver.cpp ----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Driver.h"

#include <getopt.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <string>

#include "IOChannel.h"
#include <LLDB/SBCommandInterpreter.h>
#include <LLDB/SBCommandReturnObject.h>
#include <LLDB/SBCommunication.h>
#include <LLDB/SBDebugger.h>
#include <LLDB/SBEvent.h>
#include <LLDB/SBHostOS.h>
#include <LLDB/SBListener.h>
#include <LLDB/SBSourceManager.h>
#include <LLDB/SBTarget.h>
#include <LLDB/SBThread.h>
#include <LLDB/SBProcess.h>

using namespace lldb;

static void reset_stdin_termios ();
static struct termios g_old_stdin_termios;

// In the Driver::MainLoop, we change the terminal settings.  This function is
// added as an atexit handler to make sure we clean them up.
static void
reset_stdin_termios ()
{
    ::tcsetattr (STDIN_FILENO, TCSANOW, &g_old_stdin_termios);
}

static lldb::OptionDefinition g_options[] =
{
    { 0,  true,  "help",            'h',  no_argument,        NULL,  NULL,  NULL,
        "Prints out the usage information for the LLDB debugger." },

    { 1,  true,  "version",         'v',  no_argument,        NULL,  NULL,  NULL,
        "Prints out the current version number of the LLDB debugger." },

    { 2,  false,  "file",           'f',  required_argument,  NULL,  NULL,  "<filename>",
        "Tells the debugger to use the file <filename> as the program to be debugged." },

    { 2,  false,  "arch",           'a',  required_argument,  NULL,  NULL,  "<architecture>",
        "Tells the debugger to use the specified architecture when starting and running the program.  <architecture> must be one of the architectures for which the program was compiled." },

    { 2,  false,  "script-language",'l',  required_argument,  NULL,  NULL,  "<scripting-language>",
        "Tells the debugger to use the specified scripting language for user-defined scripts, rather than the default.  Valid scripting languages that can be specified include Python, Perl, Ruby and Tcl.  Currently only the Python extensions have been implemented." },

    { 2,  false,  "debug",          'd',  no_argument,        NULL,  NULL,  NULL,
        "Tells the debugger to print out extra information for debugging itself." },

    { 2,  false,  "source",         's',  required_argument,  NULL,  NULL,  "<file>",
        "Tells the debugger to read in and execute the file <file>, which should contain lldb commands." },

    { 3,  false,  "crash-log",      'c',  required_argument,  NULL,  NULL,  "<file>",
        "Load executable images from a crash log for symbolication." },

    { 0, false, NULL, 0, 0, NULL, NULL,  NULL, NULL }
};


Driver::Driver () :
    SBBroadcaster ("Driver"),
    m_editline_pty (),
    m_editline_slave_fh (NULL),
    m_editline_reader (),
    m_io_channel_ap (),
    m_option_data (),
    m_waiting_for_command (false)
{
}

Driver::~Driver ()
{
}

void
Driver::CloseIOChannelFile ()
{
    // Write and End of File sequence to the file descriptor to ensure any
    // read functions can exit.
    char eof_str[] = "\x04";
    ::write (m_editline_pty.GetMasterFileDescriptor(), eof_str, strlen(eof_str));

    m_editline_pty.CloseMasterFileDescriptor();

    if (m_editline_slave_fh)
    {
        ::fclose (m_editline_slave_fh);
        m_editline_slave_fh = NULL;
    }
}

// This function takes INDENT, which tells how many spaces to output at the front of each line; SPACES, which is
// a string that is output_max_columns long, containing spaces; and TEXT, which is the text that is to be output.
// It outputs the text, on multiple lines if necessary, to RESULT, with INDENT spaces at the front of each line.  It
// breaks lines on spaces, tabs or newlines, shortening the line if necessary to not break in the middle of a word.
// It assumes that each output line should contain a maximum of OUTPUT_MAX_COLUMNS characters.

void
OutputFormattedUsageText (FILE *out, int indent, char *spaces, const char *text, int output_max_columns)
{
    int len = strlen (text);
    std::string text_string (text);
    std::string spaces_string (spaces);

    // Force indentation to be reasonable.
    if (indent >= output_max_columns)
        indent = 0;

    // Will it all fit on one line?

    if (len + indent < output_max_columns)
        // Output as a single line
        fprintf (out, "%s%s\n", spaces_string.substr (0, indent).c_str(), text);
    else
    {
        // We need to break it up into multiple lines.
        int text_width = output_max_columns - indent - 1;
        int start = 0;
        int end = start;
        int final_end = len;
        int sub_len;

        while (end < final_end)
        {
              // Dont start the 'text' on a space, since we're already outputting the indentation.
              while ((start < final_end) && (text[start] == ' '))
                  start++;

              end = start + text_width;
              if (end > final_end)
                  end = final_end;
              else
              {
                  // If we're not at the end of the text, make sure we break the line on white space.
                  while (end > start
                         && text[end] != ' ' && text[end] != '\t' && text[end] != '\n')
                      end--;
              }
              sub_len = end - start;
              std::string substring = text_string.substr (start, sub_len);
              fprintf (out, "%s%s\n", spaces_string.substr(0, indent).c_str(), substring.c_str());
              start = end + 1;
        }
    }
}

void
ShowUsage (FILE *out, lldb::OptionDefinition *option_table, Driver::OptionData data)
{
    uint32_t screen_width = 80;
    uint32_t indent_level = 0;
    const char *name = "lldb";
    char spaces[screen_width+1];
    uint32_t i;

    for (i = 0; i < screen_width; ++i)
      spaces[i] = ' ';
    spaces[i] = '\n';

    std::string spaces_string (spaces);

    fprintf (out, "\nUsage:\n\n");

    indent_level += 2;


    // First, show each usage level set of options, e.g. <cmd> [options-for-level-0]
    //                                                   <cmd> [options-for-level-1]
    //                                                   etc.

    uint32_t usage_level = 0;
    uint32_t num_options;

    for (num_options = 0; option_table[num_options].long_option != NULL; ++num_options);

    for (i = 0; i < num_options; ++i)
    {
        if (i == 0 || option_table[i].usage_level > usage_level)
        {
            // Start a new level.
            usage_level = option_table[i].usage_level;
            if (usage_level > 0)
                fprintf (out, "\n\n");
            fprintf (out, "%s%s", spaces_string.substr(0, indent_level).c_str(), name);
        }

        if (option_table[i].required)
        {
            if (option_table[i].option_has_arg == required_argument)
                fprintf (out, " -%c %s", option_table[i].short_option, option_table[i].argument_name);
            else if (option_table[i].option_has_arg == optional_argument)
                fprintf (out, " -%c [%s]", option_table[i].short_option, option_table[i].argument_name);
            else
                fprintf (out, " -%c", option_table[i].short_option);
        }
        else
        {
            if (option_table[i].option_has_arg == required_argument)
                fprintf (out, " [-%c %s]", option_table[i].short_option, option_table[i].argument_name);
            else if (option_table[i].option_has_arg == optional_argument)
                fprintf (out, " [-%c [%s]]", option_table[i].short_option, option_table[i].argument_name);
            else
                fprintf (out, " [-%c]", option_table[i].short_option);
        }
    }

    fprintf (out, "\n\n");

    // Now print out all the detailed information about the various options:  long form, short form and help text:
    //   -- long_name <argument>
    //   - short <argument>
    //   help text

    // This variable is used to keep track of which options' info we've printed out, because some options can be in
    // more than one usage level, but we only want to print the long form of its information once.

    Driver::OptionData::OptionSet options_seen;
    Driver::OptionData::OptionSet::iterator pos;

    indent_level += 5;

    for (i = 0; i < num_options; ++i)
    {
        // Only print this option if we haven't already seen it.
        pos = options_seen.find (option_table[i].short_option);
        if (pos == options_seen.end())
        {
            options_seen.insert (option_table[i].short_option);
            fprintf (out, "%s-%c ", spaces_string.substr(0, indent_level).c_str(), option_table[i].short_option);
            if (option_table[i].argument_name != NULL)
                fprintf (out, "%s", option_table[i].argument_name);
            fprintf (out, "\n");
            fprintf (out, "%s--%s ", spaces_string.substr(0, indent_level).c_str(), option_table[i].long_option);
            if (option_table[i].argument_name != NULL)
                fprintf (out, "%s", option_table[i].argument_name);
            fprintf (out, "\n");
            indent_level += 5;
            OutputFormattedUsageText (out, indent_level, spaces, option_table[i].usage_text, screen_width);
            indent_level -= 5;
            fprintf (out, "\n");
        }
    }

    indent_level -= 5;

    fprintf (out, "\n%s('%s <filename>' also works, to specify the file to be debugged.)\n\n",
             spaces_string.substr(0, indent_level).c_str(), name);
}

void
BuildGetOptTable (lldb::OptionDefinition *expanded_option_table, struct option **getopt_table, int num_options)
{
    if (num_options == 0)
        return;

    uint32_t i;
    uint32_t j;
    std::bitset<256> option_seen;

    for (i = 0, j = 0; i < num_options; ++i)
      {
        char short_opt = expanded_option_table[i].short_option;

        if (option_seen.test(short_opt) == false)
          {
            (*getopt_table)[j].name    = expanded_option_table[i].long_option;
            (*getopt_table)[j].has_arg = expanded_option_table[i].option_has_arg;
            (*getopt_table)[j].flag    = NULL;
            (*getopt_table)[j].val     = expanded_option_table[i].short_option;
            option_seen.set(short_opt);
            ++j;
          }
      }

    (*getopt_table)[j].name    = NULL;
    (*getopt_table)[j].has_arg = 0;
    (*getopt_table)[j].flag    = NULL;
    (*getopt_table)[j].val     = 0;

}

SBError
ParseOptions (Driver::OptionData &data, int argc, const char **argv)
{
    SBError error;
    std::string option_string;
    struct option *long_options = NULL;
    int num_options;

    for (num_options = 0; g_options[num_options].long_option != NULL; ++num_options);

    if (num_options == 0)
    {
        if (argc > 1)
            error.SetErrorStringWithFormat ("invalid number of options");
        return error;
    }

    long_options = (struct option *) malloc ((num_options + 1) * sizeof (struct option));

    BuildGetOptTable (g_options, &long_options, num_options);

    if (long_options == NULL)
    {
        error.SetErrorStringWithFormat ("invalid long options");
        return error;
    }

    // Build the option_string argument for call to getopt_long.

    for (int i = 0; long_options[i].name != NULL; ++i)
    {
        if (long_options[i].flag == NULL)
        {
            option_string.push_back ((char) long_options[i].val);
            switch (long_options[i].has_arg)
            {
                default:
                case no_argument:
                    break;
                case required_argument:
                    option_string.push_back (':');
                    break;
                case optional_argument:
                    option_string.append ("::");
                    break;
            }
        }
    }

    // Prepare for & make calls to getopt_long.

    optreset = 1;
    optind = 1;
    int val;
    while (1)
    {
        int long_options_index = -1;
        val = ::getopt_long (argc, (char * const *) argv, option_string.c_str(), long_options, &long_options_index);

        if (val == -1)
            break;
        else if (val == '?')
        {
            data.m_print_help = true;
            error.SetErrorStringWithFormat ("unknown or ambiguous option");
            break;
        }
        else if (val == 0)
            continue;
        else
        {
            data.m_seen_options.insert ((char) val);
            if (long_options_index == -1)
            {
                for (int i = 0;
                     long_options[i].name || long_options[i].has_arg || long_options[i].flag || long_options[i].val;
                     ++i)
                {
                    if (long_options[i].val == val)
                    {
                        long_options_index = i;
                        break;
                    }
                }
            }

            if (long_options_index >= 0)
            {
                error = Driver::SetOptionValue (long_options_index,
                                                long_options[long_options_index].has_arg == no_argument ? NULL : optarg,
                                                data);
            }
            else
            {
                error.SetErrorStringWithFormat ("invalid option with value %i", val);
            }
            if (error.Fail())
                break;
        }
    }

    return error;
}

Driver::OptionData::OptionData () :
    m_filename(),
    m_script_lang (lldb::eScriptLanguageDefault),
    m_source_command_files (),
    m_debug_mode (false),
    m_print_help (false),
    m_print_version (false)

{
}

Driver::OptionData::~OptionData ()
{
}

void
Driver::OptionData::Clear ()
{
    m_filename.clear ();
    m_script_lang = lldb::eScriptLanguageDefault;
    m_source_command_files.clear ();
    m_debug_mode = false;
    m_print_help = false;
    m_print_version = false;
}

SBError
Driver::SetOptionValue (int option_idx, const char *option_arg, Driver::OptionData &option_data)
{
    SBError error;
    const char short_option = (char) g_options[option_idx].short_option;

    switch (short_option)
    {
        case 'h':
            option_data.m_print_help = true;
            break;

        case 'v':
            option_data.m_print_version = true;
            break;

        case 'c':
            option_data.m_crash_log = option_arg;
            break;

        case 'f':
            {
                SBFileSpec file(option_arg);
                if (file.Exists())
                    option_data.m_filename = option_arg;
                else
                    error.SetErrorStringWithFormat("file specified in --file (-f) option doesn't exist: '%s'", option_arg);
            }
            break;

        case 'a':
            if (!SBDebugger::SetDefaultArchitecture (option_arg))
                error.SetErrorStringWithFormat("invalid architecture in the -a or --arch option: '%s'", option_arg);
            break;

        case 'l':
            option_data.m_script_lang = SBDebugger::GetScriptingLanguage (option_arg);
            break;

        case 'd':
            option_data.m_debug_mode = true;
            break;

        case 's':
            {
                SBFileSpec file(option_arg);
                if (file.Exists())
                    option_data.m_source_command_files.push_back (option_arg);
                else
                    error.SetErrorStringWithFormat("file specified in --source (-s) option doesn't exist: '%s'", option_arg);
            }
            break;

        default:
            option_data.m_print_help = true;
            error.SetErrorStringWithFormat ("unrecognized option %c", short_option);
            break;
    }

    return error;
}

void
Driver::ResetOptionValues ()
{
    m_option_data.Clear ();
}

const char *
Driver::GetFilename() const
{
    if (m_option_data.m_filename.empty())
        return NULL;
    return m_option_data.m_filename.c_str();
}

const char *
Driver::GetCrashLogFilename() const
{
    if (m_option_data.m_crash_log.empty())
        return NULL;
    return m_option_data.m_crash_log.c_str();
}

lldb::ScriptLanguage
Driver::GetScriptLanguage() const
{
    return m_option_data.m_script_lang;
}

size_t
Driver::GetNumSourceCommandFiles () const
{
    return m_option_data.m_source_command_files.size();
}

const char *
Driver::GetSourceCommandFileAtIndex (uint32_t idx) const
{
    if (idx < m_option_data.m_source_command_files.size())
        return m_option_data.m_source_command_files[idx].c_str();
    return NULL;
}

bool
Driver::GetDebugMode() const
{
    return m_option_data.m_debug_mode;
}


// Check the arguments that were passed to this program to make sure they are valid and to get their
// argument values (if any).  Return a boolean value indicating whether or not to start up the full
// debugger (i.e. the Command Interpreter) or not.  Return FALSE if the arguments were invalid OR
// if the user only wanted help or version information.

bool
Driver::ParseArgs (int argc, const char *argv[], FILE *out_fh, FILE *err_fh)
{
    bool valid = true;

    ResetOptionValues ();

    if (argc == 2 && *(argv[1]) != '-')
    {
        m_option_data.m_filename = argv[1];
    }
    else
    {
        SBCommandReturnObject result;

        SBError error = ParseOptions (m_option_data, argc, argv);
        if (error.Fail())
        {
            const char *error_cstr = error.GetCString ();
            if (error_cstr)
                ::fprintf (err_fh, "error: %s\n", error_cstr);
        }
    }

    // Check to see if they just invoked the debugger with a filename.


    if (m_option_data.m_print_help)
    {
        ShowUsage (out_fh, g_options, m_option_data);
        valid = false;
    }
    else if (m_option_data.m_print_version)
    {
        ::fprintf (out_fh, "%s\n", SBDebugger::GetVersionString());
        valid = false;
    }
    else if (! m_option_data.m_crash_log.empty())
    {
        // Handle crash log stuff here.
    }
    else
    {
        // All other combinations are valid; do nothing more here.
    }

    return valid;
}

void
Driver::GetProcessSTDOUT ()
{
    //  The process has stuff waiting for stdout; get it and write it out to the appropriate place.
    char stdio_buffer[1024];
    size_t len;
    while ((len = SBDebugger::GetCurrentTarget().GetProcess().GetSTDOUT (stdio_buffer, sizeof (stdio_buffer))) > 0)
        m_io_channel_ap->OutWrite (stdio_buffer, len);
}

void
Driver::GetProcessSTDERR ()
{
    //  The process has stuff waiting for stderr; get it and write it out to the appropriate place.
    char stdio_buffer[1024];
    size_t len;
    while ((len = SBDebugger::GetCurrentTarget().GetProcess().GetSTDERR (stdio_buffer, sizeof (stdio_buffer))) > 0)
        m_io_channel_ap->ErrWrite (stdio_buffer, len);
}

void
Driver::UpdateCurrentThread ()
{
    using namespace lldb;
    SBProcess process(SBDebugger::GetCurrentTarget().GetProcess());
    if (process.IsValid())
    {
        SBThread curr_thread (process.GetCurrentThread());
        SBThread thread;
        StopReason curr_thread_stop_reason = eStopReasonInvalid;
        curr_thread_stop_reason = curr_thread.GetStopReason();

        if (!curr_thread.IsValid() ||
            curr_thread_stop_reason == eStopReasonInvalid ||
            curr_thread_stop_reason == eStopReasonNone)
        {
            // Prefer a thread that has just completed its plan over another thread as current thread.
            SBThread plan_thread;
            SBThread other_thread;
            const size_t num_threads = process.GetNumThreads();
            size_t i;
            for (i = 0; i < num_threads; ++i)
            {
                thread = process.GetThreadAtIndex(i);
                StopReason thread_stop_reason = thread.GetStopReason();
                switch (thread_stop_reason)
                {
                default:
                case eStopReasonInvalid:
                case eStopReasonNone:
                    break;

                case eStopReasonTrace:
                case eStopReasonBreakpoint:
                case eStopReasonWatchpoint:
                case eStopReasonSignal:
                case eStopReasonException:
                    if (!other_thread.IsValid())
                        other_thread = thread;
                    break;
                case eStopReasonPlanComplete:
                    if (!plan_thread.IsValid())
                        plan_thread = thread;
                    break;
                }
            }
            if (plan_thread.IsValid())
                process.SetCurrentThread (plan_thread);
            else if (other_thread.IsValid())
                process.SetCurrentThread (other_thread);
            else
            {
                if (curr_thread.IsValid())
                    thread = curr_thread;
                else
                    thread = process.GetThreadAtIndex(0);

                if (thread.IsValid())
                    process.SetCurrentThread (thread);
            }
        }
    }
}


// This function handles events that were broadcast by the process.
void
Driver::HandleProcessEvent (const SBEvent &event)
{
    using namespace lldb;
    const uint32_t event_type = event.GetType();

    if (event_type & SBProcess::eBroadcastBitSTDOUT)
    {
        // The process has stdout available, get it and write it out to the
        // appropriate place.
        GetProcessSTDOUT ();
    }
    else if (event_type & SBProcess::eBroadcastBitSTDERR)
    {
        // The process has stderr available, get it and write it out to the
        // appropriate place.
        GetProcessSTDERR ();
    }
    else if (event_type & SBProcess::eBroadcastBitStateChanged)
    {
        // Drain all stout and stderr so we don't see any output come after
        // we print our prompts
        GetProcessSTDOUT ();
        GetProcessSTDERR ();

        // Something changed in the process;  get the event and report the process's current status and location to
        // the user.
        StateType event_state = SBProcess::GetStateFromEvent (event);
        if (event_state == eStateInvalid)
            return;

        SBProcess process (SBProcess::GetProcessFromEvent (event));
        assert (process.IsValid());

        switch (event_state)
        {
        case eStateInvalid:
        case eStateUnloaded:
        case eStateAttaching:
        case eStateLaunching:
        case eStateStepping:
        case eStateDetached:
            {
                char message[1024];
                int message_len = ::snprintf (message, sizeof(message), "Process %d %s\n", process.GetProcessID(),
                                              SBDebugger::StateAsCString (event_state));
                m_io_channel_ap->OutWrite(message, message_len);
            }
            break;

        case eStateRunning:
            // Don't be chatty when we run...
            break;

        case eStateExited:
            SBDebugger::HandleCommand("status");
            m_io_channel_ap->RefreshPrompt();
            break;

        case eStateStopped:
        case eStateCrashed:
        case eStateSuspended:
            // Make sure the program hasn't been auto-restarted:
            if (SBProcess::GetRestartedFromEvent (event))
            {
                // FIXME: Do we want to report this, or would that just be annoyingly chatty?
                char message[1024];
                int message_len = ::snprintf (message, sizeof(message), "Process %d stopped and was programmatically restarted.\n",
                                              process.GetProcessID());
                m_io_channel_ap->OutWrite(message, message_len);
            }
            else
            {
                UpdateCurrentThread ();
                SBDebugger::HandleCommand("status");
                m_io_channel_ap->RefreshPrompt();
            }
            break;
        }
    }
}

//  This function handles events broadcast by the IOChannel (HasInput, UserInterrupt, or ThreadShouldExit).

bool
Driver::HandleIOEvent (const SBEvent &event)
{
    bool quit = false;

    const uint32_t event_type = event.GetType();

    if (event_type & IOChannel::eBroadcastBitHasUserInput)
    {
        // We got some input (i.e. a command string) from the user; pass it off to the command interpreter for
        // handling.

        const char *command_string = SBEvent::GetCStringFromEvent(event);
        if (command_string == NULL)
            command_string == "";
        SBCommandReturnObject result;
        if (SBDebugger::GetCommandInterpreter().HandleCommand (command_string, result, true) != lldb::eReturnStatusQuit)
        {
            m_io_channel_ap->ErrWrite (result.GetError(), result.GetErrorSize());
            m_io_channel_ap->OutWrite (result.GetOutput(), result.GetOutputSize());
        }
        // We are done getting and running our command, we can now clear the
        // m_waiting_for_command so we can get another one.
        m_waiting_for_command = false;

        // If our editline input reader is active, it means another input reader
        // got pushed onto the input reader and caused us to become deactivated.
        // When the input reader above us gets popped, we will get re-activated
        // and our prompt will refresh in our callback
        if (m_editline_reader.IsActive())
        {
            ReadyForCommand ();
        }
    }
    else if (event_type & IOChannel::eBroadcastBitUserInterrupt)
    {
        // This is here to handle control-c interrupts from the user.  It has not yet really been implemented.
        // TO BE DONE:  PROPERLY HANDLE CONTROL-C FROM USER
        //m_io_channel_ap->CancelInput();
        // Anything else?  Send Interrupt to process?
    }
    else if ((event_type & IOChannel::eBroadcastBitThreadShouldExit) ||
             (event_type & IOChannel::eBroadcastBitThreadDidExit))
    {
        // If the IOChannel thread is trying to go away, then it is definitely
        // time to end the debugging session.
        quit = true;
    }

    return quit;
}


//struct CrashImageInfo
//{
//    std::string path;
//    VMRange text_range;
//    UUID uuid;
//};
//
//void
//Driver::ParseCrashLog (const char *crash_log)
//{
//    printf("Parsing crash log: %s\n", crash_log);
//
//    char image_path[PATH_MAX];
//    std::vector<CrashImageInfo> crash_infos;
//    if (crash_log && crash_log[0])
//    {
//        FileSpec crash_log_file (crash_log);
//        STLStringArray crash_log_lines;
//        if (crash_log_file.ReadFileLines (crash_log_lines))
//        {
//            const size_t num_crash_log_lines = crash_log_lines.size();
//            size_t i;
//            for (i=0; i<num_crash_log_lines; ++i)
//            {
//                const char *line = crash_log_lines[i].c_str();
//                if (strstr (line, "Code Type:"))
//                {
//                    char arch_string[256];
//                    if (sscanf(line, "%s", arch_string))
//                    {
//                        if (strcmp(arch_string, "X86-64"))
//                            lldb::GetDefaultArchitecture ().SetArch ("x86_64");
//                        else if (strcmp(arch_string, "X86"))
//                            lldb::GetDefaultArchitecture ().SetArch ("i386");
//                        else
//                        {
//                            ArchSpec arch(arch_string);
//                            if (arch.IsValid ())
//                                lldb::GetDefaultArchitecture () = arch;
//                            else
//                                fprintf(stderr, "Unrecognized architecture: %s\n", arch_string);
//                        }
//                    }
//                }
//                else
//                if (strstr(line, "Path:"))
//                {
//                    const char *p = line + strlen("Path:");
//                    while (isspace(*p))
//                        ++p;
//
//                    m_option_data.m_filename.assign (p);
//                }
//                else
//                if (strstr(line, "Binary Images:"))
//                {
//                    while (++i < num_crash_log_lines)
//                    {
//                        if (crash_log_lines[i].empty())
//                            break;
//
//                        line = crash_log_lines[i].c_str();
//                        uint64_t text_start_addr;
//                        uint64_t text_end_addr;
//                        char uuid_cstr[64];
//                        int bytes_consumed_before_uuid = 0;
//                        int bytes_consumed_after_uuid = 0;
//
//                        int items_parsed = ::sscanf (line,
//                                                     "%llx - %llx %*s %*s %*s %n%s %n",
//                                                     &text_start_addr,
//                                                     &text_end_addr,
//                                                     &bytes_consumed_before_uuid,
//                                                     uuid_cstr,
//                                                     &bytes_consumed_after_uuid);
//
//                        if (items_parsed == 3)
//                        {
//
//                            CrashImageInfo info;
//                            info.text_range.SetBaseAddress(text_start_addr);
//                            info.text_range.SetEndAddress(text_end_addr);
//
//                            if (uuid_cstr[0] == '<')
//                            {
//                                if (info.uuid.SetfromCString (&uuid_cstr[1]) == 0)
//                                    info.uuid.Clear();
//
//                                ::strncpy (image_path, line + bytes_consumed_after_uuid, sizeof(image_path));
//                            }
//                            else
//                            {
//                                ::strncpy (image_path, line + bytes_consumed_before_uuid, sizeof(image_path));
//                            }
//
//                            info.path = image_path;
//
//                            crash_infos.push_back (info);
//
//                            info.uuid.GetAsCString(uuid_cstr, sizeof(uuid_cstr));
//
//                            printf("0x%16.16llx - 0x%16.16llx <%s> %s\n",
//                                   text_start_addr,
//                                   text_end_addr,
//                                   uuid_cstr,
//                                   image_path);
//                        }
//                    }
//                }
//            }
//        }
//
//        if (crash_infos.size())
//        {
//            SBTarget target (SBDebugger::CreateTarget (crash_infos.front().path.c_str(),
//                                                      lldb::GetDefaultArchitecture().AsCString (),
//                                                      false));
//            if (target.IsValid())
//            {
//
//            }
//        }
//    }
//}
//

void
Driver::MasterThreadBytesReceived (void *baton, const void *src, size_t src_len)
{
    Driver *driver = (Driver*)baton;
    driver->GetFromMaster ((const char *)src, src_len);
}

void
Driver::GetFromMaster (const char *src, size_t src_len)
{
    // Echo the characters back to the Debugger's stdout, that way if you
    // type characters while a command is running, you'll see what you've typed.
    FILE *out_fh = SBDebugger::GetOutputFileHandle();
    if (out_fh)
        ::fwrite (src, 1, src_len, out_fh);
}

size_t
Driver::EditLineInputReaderCallback 
(
    void *baton, 
    SBInputReader *reader, 
    InputReaderAction notification,
    const char *bytes, 
    size_t bytes_len
)
{
    Driver *driver = (Driver *)baton;

    switch (notification)
    {
    case eInputReaderActivate:
        break;

    case eInputReaderReactivate:
        driver->ReadyForCommand();
        break;

    case eInputReaderDeactivate:
        break;

    case eInputReaderGotToken:
        write (driver->m_editline_pty.GetMasterFileDescriptor(), bytes, bytes_len);
        break;
        
    case eInputReaderDone:
        break;
    }
    return bytes_len;
}

void
Driver::MainLoop ()
{
    char error_str[1024];
    if (m_editline_pty.OpenFirstAvailableMaster(O_RDWR|O_NOCTTY, error_str, sizeof(error_str)) == false)
    {
        ::fprintf (stderr, "error: failed to open driver pseudo terminal : %s", error_str);
        exit(1);
    }
    else
    {
        const char *driver_slave_name = m_editline_pty.GetSlaveName (error_str, sizeof(error_str));
        if (driver_slave_name == NULL)
        {
            ::fprintf (stderr, "error: failed to get slave name for driver pseudo terminal : %s", error_str);
            exit(2);
        }
        else
        {
            m_editline_slave_fh = ::fopen (driver_slave_name, "r+");
            if (m_editline_slave_fh == NULL)
            {
                SBError error;
                error.SetErrorToErrno();
                ::fprintf (stderr, "error: failed to get open slave for driver pseudo terminal : %s",
                           error.GetCString());
                exit(3);
            }

            ::setbuf (m_editline_slave_fh, NULL);
        }
    }


   // struct termios stdin_termios;

    if (::tcgetattr(STDIN_FILENO, &g_old_stdin_termios) == 0)
        atexit (reset_stdin_termios);

    ::setbuf (stdin, NULL);
    ::setbuf (stdout, NULL);

    SBDebugger::SetErrorFileHandle (stderr, false);
    SBDebugger::SetOutputFileHandle (stdout, false);
    SBDebugger::SetInputFileHandle (stdin, true);

    // You have to drain anything that comes to the master side of the PTY.  master_out_comm is
    // for that purpose.  The reason you need to do this is a curious reason...  editline will echo
    // characters to the PTY when it gets characters while el_gets is not running, and then when
    // you call el_gets (or el_getc) it will try to reset the terminal back to raw mode which blocks
    // if there are unconsumed characters in the out buffer.
    // However, you don't need to do anything with the characters, since editline will dump these
    // unconsumed characters after printing the prompt again in el_gets.

    SBCommunication master_out_comm("driver.editline");
    master_out_comm.AdoptFileDesriptor(m_editline_pty.GetMasterFileDescriptor(), false);
    master_out_comm.SetReadThreadBytesReceivedCallback(Driver::MasterThreadBytesReceived, this);

    if (master_out_comm.ReadThreadStart () == false)
    {
        ::fprintf (stderr, "error: failed to start master out read thread");
        exit(5);
    }

//    const char *crash_log = GetCrashLogFilename();
//    if (crash_log)
//    {
//        ParseCrashLog (crash_log);
//    }
//
    SBCommandInterpreter sb_interpreter = SBDebugger::GetCommandInterpreter();

    m_io_channel_ap.reset (new IOChannel(m_editline_slave_fh, stdout, stderr, this));

    struct winsize window_size;
    if (isatty (STDIN_FILENO)
        && ::ioctl (STDIN_FILENO, TIOCGWINSZ, &window_size) == 0)
    {
        char buffer[25];

        sprintf (buffer, "set term-width %d", window_size.ws_col);
        SBDebugger::HandleCommand ((const char *) buffer);
    }

    // Since input can be redirected by the debugger, we must insert our editline
    // input reader in the queue so we know when our reader should be active
    // and so we can receive bytes only when we are supposed to.
    SBError err (m_editline_reader.Initialize (Driver::EditLineInputReaderCallback, // callback
                                               this,                              // baton
                                               eInputReaderGranularityByte,       // token_size
                                               NULL,                              // end token - NULL means never done
                                               NULL,                              // prompt - taken care of elsewhere
                                               false));                           // echo input - don't need Debugger 
                                                                                  // to do this, we handle it elsewhere
    
    if (err.Fail())
    {
        ::fprintf (stderr, "error: %s", err.GetCString());
        exit (6);
    }
    
    SBDebugger::PushInputReader (m_editline_reader);

    SBListener listener(SBDebugger::GetListener());
    if (listener.IsValid())
    {

        listener.StartListeningForEvents (*m_io_channel_ap,
                                          IOChannel::eBroadcastBitHasUserInput |
                                          IOChannel::eBroadcastBitUserInterrupt |
                                          IOChannel::eBroadcastBitThreadShouldExit |
                                          IOChannel::eBroadcastBitThreadDidStart |
                                          IOChannel::eBroadcastBitThreadDidExit);

        if (m_io_channel_ap->Start ())
        {
            bool iochannel_thread_exited = false;

            listener.StartListeningForEvents (sb_interpreter.GetBroadcaster(),
                                              SBCommandInterpreter::eBroadcastBitQuitCommandReceived);

            // Before we handle any options from the command line, we parse the
            // .lldbinit file in the user's home directory.
            SBCommandReturnObject result;
            sb_interpreter.SourceInitFileInHomeDirectory(result);
            if (GetDebugMode())
            {
                result.PutError (SBDebugger::GetErrorFileHandle());
                result.PutOutput (SBDebugger::GetOutputFileHandle());
            }

            // Now we handle options we got from the command line
            char command_string[PATH_MAX * 2];
            const size_t num_source_command_files = GetNumSourceCommandFiles();
            if (num_source_command_files > 0)
            {
                for (size_t i=0; i < num_source_command_files; ++i)
                {
                    const char *command_file = GetSourceCommandFileAtIndex(i);
                    ::snprintf (command_string, sizeof(command_string), "source '%s'", command_file);
                    SBDebugger::GetCommandInterpreter().HandleCommand (command_string, result, false);
                    if (GetDebugMode())
                    {
                        result.PutError (SBDebugger::GetErrorFileHandle());
                        result.PutOutput (SBDebugger::GetOutputFileHandle());
                    }
                }
            }

            if (!m_option_data.m_filename.empty())
            {
                char arch_name[64];
                if (SBDebugger::GetDefaultArchitecture (arch_name, sizeof (arch_name)))
                    ::snprintf (command_string, sizeof (command_string), "file --arch=%s '%s'", arch_name,
                                m_option_data.m_filename.c_str());
                else
                    ::snprintf (command_string, sizeof(command_string), "file '%s'", m_option_data.m_filename.c_str());

                SBDebugger::HandleCommand (command_string);
            }

            // Now that all option parsing is done, we try and parse the .lldbinit
            // file in the current working directory
            sb_interpreter.SourceInitFileInCurrentWorkingDirectory (result);
            if (GetDebugMode())
            {
                result.PutError(SBDebugger::GetErrorFileHandle());
                result.PutOutput(SBDebugger::GetOutputFileHandle());
            }

            SBEvent event;

            // Make sure the IO channel is started up before we try to tell it we
            // are ready for input
            listener.WaitForEventForBroadcasterWithType (UINT32_MAX, 
                                                         *m_io_channel_ap,
                                                         IOChannel::eBroadcastBitThreadDidStart, 
                                                         event);
            
            ReadyForCommand ();

            bool done = false;
            while (!done)
            {
                listener.WaitForEvent (UINT32_MAX, event);
                if (event.IsValid())
                {
                    if (event.GetBroadcaster().IsValid())
                    {
                        uint32_t event_type = event.GetType();
                        if (event.BroadcasterMatchesRef (*m_io_channel_ap))
                        {
                            if ((event_type & IOChannel::eBroadcastBitThreadShouldExit) ||
                                (event_type & IOChannel::eBroadcastBitThreadDidExit))
                            {
                                done = true;
                                if (event_type & IOChannel::eBroadcastBitThreadDidExit)
                                    iochannel_thread_exited = true;
                                break;
                            }
                            else
                                done = HandleIOEvent (event);
                        }
                        else if (event.BroadcasterMatchesRef (SBDebugger::GetCurrentTarget().GetProcess().GetBroadcaster()))
                        {
                            HandleProcessEvent (event);
                        }
                        else if (event.BroadcasterMatchesRef (sb_interpreter.GetBroadcaster()))
                        {
                            if (event_type & SBCommandInterpreter::eBroadcastBitQuitCommandReceived)
                                done = true;
                        }
                    }
                }
            }

            reset_stdin_termios ();

            CloseIOChannelFile ();

            if (!iochannel_thread_exited)
            {
                SBEvent event;
                listener.GetNextEventForBroadcasterWithType (*m_io_channel_ap,
                                                             IOChannel::eBroadcastBitThreadDidExit,
                                                             event);
                if (!event.IsValid())
                {
                    // Send end EOF to the driver file descriptor
                    m_io_channel_ap->Stop();
                }
            }

            SBProcess process = SBDebugger::GetCurrentTarget().GetProcess();
            if (process.IsValid())
                process.Destroy();
        }
    }
}


void
Driver::ReadyForCommand ()
{
    if (m_waiting_for_command == false)
    {
        m_waiting_for_command = true;
        BroadcastEventByType (Driver::eBroadcastBitReadyForInput, true);
    }
}


int
main (int argc, char const *argv[])
{

    SBDebugger::Initialize();
    
    SBHostOS::ThreadCreated ("[main]");

    // Do a little setup on the debugger before we get going
    SBDebugger::SetAsync(true);
    Driver driver;

    bool valid_args = driver.ParseArgs (argc, argv, stdout, stderr);
    if (valid_args)
    {
        driver.MainLoop ();
    }

    SBDebugger::Terminate();
    return 0;
}
