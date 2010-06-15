//===-- CommandObjectBreakpointCommand.cpp ----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
// C++ Includes


#include "CommandObjectBreakpointCommand.h"
#include "CommandObjectBreakpoint.h"

#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Breakpoint/BreakpointIDList.h"
#include "lldb/Breakpoint/Breakpoint.h"
#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Breakpoint/StoppointCallbackContext.h"
#include "lldb/Core/State.h"

using namespace lldb;
using namespace lldb_private;

//-------------------------------------------------------------------------
// CommandObjectBreakpointCommandAdd::CommandOptions
//-------------------------------------------------------------------------

CommandObjectBreakpointCommandAdd::CommandOptions::CommandOptions () :
    Options ()
{
    BuildValidOptionSets();
}

CommandObjectBreakpointCommandAdd::CommandOptions::~CommandOptions ()
{
}

lldb::OptionDefinition
CommandObjectBreakpointCommandAdd::CommandOptions::g_option_table[] =
{
    { LLDB_OPT_SET_1, true, "script",    's', no_argument, NULL, 0, NULL,
        "Write the breakpoint command script in the default scripting language."},

    { LLDB_OPT_SET_2, true, "python",    'p', no_argument, NULL, 0, NULL,
        "Write the breakpoint command script in the Python scripting language."},

    { LLDB_OPT_SET_3, true, "commands",  'c', no_argument, NULL, 0, NULL,
        "Write the breakpoint command script using the command line commands."},

    { 0, false, NULL, 0, 0, NULL, 0, NULL, NULL }
};

const lldb::OptionDefinition*
CommandObjectBreakpointCommandAdd::CommandOptions::GetDefinitions ()
{
    return g_option_table;
}


Error
CommandObjectBreakpointCommandAdd::CommandOptions::SetOptionValue 
(
    int option_idx, 
    const char *option_arg
)
{
    Error error;
    char short_option = (char) m_getopt_table[option_idx].val;

    switch (short_option)
      {
      case 's':
        m_use_commands = false;
        m_use_script_language = true;
        m_script_language = eScriptLanguageDefault;
        break;
      case 'p':
        m_use_commands = false;
        m_use_script_language = true;
        m_script_language = eScriptLanguagePython;
        break;
      case 'c':
        m_use_commands = true;
        m_use_script_language = false;
        m_script_language = eScriptLanguageNone;
        break;
      default:
        break;
      }
    return error;
}

void
CommandObjectBreakpointCommandAdd::CommandOptions::ResetOptionValues ()
{
    Options::ResetOptionValues();

    m_use_commands = false;
    m_use_script_language = false;
    m_script_language = eScriptLanguageNone;
}

//-------------------------------------------------------------------------
// CommandObjectBreakpointCommandAdd
//-------------------------------------------------------------------------


CommandObjectBreakpointCommandAdd::CommandObjectBreakpointCommandAdd () :
    CommandObject ("add",
                   "Adds a set of commands to a breakpoint to be executed whenever a breakpoint is hit.",
                   "breakpoint command add <cmd-options> <breakpoint-id>")
{
    SetHelpLong (
"\nGeneral information about entering breakpoint commands \n\
------------------------------------------------------ \n\
 \n\
This command will cause you to be prompted to enter the command or set \n\
of commands you wish to be executed when the specified breakpoint is \n\
hit.  You will be told to enter your command(s), and will see a '> ' \n\
prompt. Because you can enter one or many commands to be executed when \n\
a breakpoint is hit, you will continue to be prompted after each \n\
new-line that you enter, until you enter the word 'DONE', which will \n\
cause the commands you have entered to be stored with the breakpoint \n\
and executed when the breakpoint is hit. \n\
 \n\
Syntax checking is not necessarily done when breakpoint commands are \n\
entered.  An improperly written breakpoint command will attempt to get \n\
executed when the breakpoint gets hit, and usually silently fail.  If \n\
your breakpoint command does not appear to be getting executed, go \n\
back and check your syntax. \n\
 \n\
 \n\
Special information about PYTHON breakpoint commands \n\
---------------------------------------------------- \n\
 \n\
You may enter either one line of Python or multiple lines of Python \n\
(including defining whole functions, if desired).  If you enter a \n\
single line of Python, that will be passed to the Python interpreter \n\
'as is' when the breakpoint gets hit.  If you enter function \n\
definitions, they will be passed to the Python interpreter as soon as \n\
you finish entering the breakpoint command, and they can be called \n\
later (don't forget to add calls to them, if you want them called when \n\
the breakpoint is hit).  If you enter multiple lines of Python that \n\
are not function definitions, they will be collected into a new, \n\
automatically generated Python function, and a call to the newly \n\
generated function will be attached to the breakpoint.  Important \n\
Note: Because loose Python code gets collected into functions, if you \n\
want to access global variables in the 'loose' code, you need to \n\
specify that they are global, using the 'global' keyword.  Be sure to \n\
use correct Python syntax, including indentation, when entering Python \n\
breakpoint commands. \n\
 \n\
Example Python one-line breakpoint command: \n\
 \n\
(lldb) breakpoint command add -p 1 \n\
Enter your Python command(s). Type 'DONE' to end. \n\
> print \"Hit this breakpoint!\" \n\
> DONE \n\
 \n\
Example multiple line Python breakpoint command, using function definition: \n\
 \n\
(lldb) breakpoint command add -p 1 \n\
Enter your Python command(s). Type 'DONE' to end. \n\
> def breakpoint_output (bp_no): \n\
>     out_string = \"Hit breakpoint number \" + repr (bp_no) \n\
>     print out_string \n\
>     return True \n\
> breakpoint_output (1) \n\
> DONE \n\
 \n\
 \n\
Example multiple line Python breakpoint command, using 'loose' Python: \n\
 \n\
(lldb) breakpoint command add -p 1 \n\
Enter your Python command(s). Type 'DONE' to end. \n\
> global bp_count \n\
> bp_count = bp_count + 1 \n\
> print \"Hit this breakpoint \" + repr(bp_count) + \" times!\" \n\
> DONE \n\
 \n\
In this case, since there is a reference to a global variable, \n\
'bp_count', you will also need to make sure 'bp_count' exists and is \n\
initialized: \n\
 \n\
(lldb) script \n\
>>> bp_count = 0 \n\
>>> quit() \n\
 \n\
(lldb)  \n\
 \n\
Special information  debugger command breakpoint commands \n\
--------------------------------------------------------- \n\
 \n\
You may enter any debugger command, exactly as you would at the \n\
debugger prompt.  You may enter as many debugger commands as you like, \n\
but do NOT enter more than one command per line. \n" );
}

CommandObjectBreakpointCommandAdd::~CommandObjectBreakpointCommandAdd ()
{
}

bool
CommandObjectBreakpointCommandAdd::Execute 
(
    Args& command,
    CommandContext *context,
    CommandInterpreter *interpreter,
    CommandReturnObject &result
)
{
    Target *target = context->GetTarget();

    if (target == NULL)
    {
        result.AppendError ("There is not a current executable; there are no breakpoints to which to add commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    const BreakpointList &breakpoints = target->GetBreakpointList();
    size_t num_breakpoints = breakpoints.GetSize();

    if (num_breakpoints == 0)
    {
        result.AppendError ("No breakpoints exist to have commands added");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    if (command.GetArgumentCount() == 0)
    {
        result.AppendError ("No breakpoint specified to which to add the commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    BreakpointIDList valid_bp_ids;
    CommandObjectMultiwordBreakpoint::VerifyBreakpointIDs (command, target, result, &valid_bp_ids);

    if (result.Succeeded())
    {
        for (int i = 0; i < valid_bp_ids.Size(); ++i)
        {
            BreakpointID cur_bp_id = valid_bp_ids.GetBreakpointIDAtIndex (i);
            if (cur_bp_id.GetBreakpointID() != LLDB_INVALID_BREAK_ID)
            {
                Breakpoint *bp = target->GetBreakpointByID (cur_bp_id.GetBreakpointID()).get();
                if (cur_bp_id.GetLocationID() != LLDB_INVALID_BREAK_ID)
                {
                    BreakpointLocationSP bp_loc_sp(bp->FindLocationByID (cur_bp_id.GetLocationID()));
                    if (bp_loc_sp)
                    {
                        if (m_options.m_use_script_language)
                        {
                            interpreter->GetScriptInterpreter()->CollectDataForBreakpointCommandCallback (bp_loc_sp->GetLocationOptions(),
                                                                                                          result);
                        }
                        else
                        {
                            CollectDataForBreakpointCommandCallback (bp_loc_sp->GetLocationOptions(), result);
                        }
                    }
                }
                else
                {
                    if (m_options.m_use_script_language)
                    {
                        interpreter->GetScriptInterpreter()->CollectDataForBreakpointCommandCallback (bp->GetOptions(),
                                                                                                      result);
                    }
                    else
                    {
                        CollectDataForBreakpointCommandCallback (bp->GetOptions(), result);
                    }
                }
            }
        }
    }

    return result.Succeeded();
}

Options *
CommandObjectBreakpointCommandAdd::GetOptions ()
{
    return &m_options;
}

const char *g_reader_instructions = "Enter your debugger command(s).  Type 'DONE' to end.";

void
CommandObjectBreakpointCommandAdd::CollectDataForBreakpointCommandCallback
(
    BreakpointOptions *bp_options,
    CommandReturnObject &result
)
{
    InputReaderSP reader_sp (new InputReader());
    std::auto_ptr<BreakpointOptions::CommandData> data_ap(new BreakpointOptions::CommandData());
    if (reader_sp && data_ap.get())
    {
        BatonSP baton_sp (new BreakpointOptions::CommandBaton (data_ap.release()));
        bp_options->SetCallback (CommandObjectBreakpointCommand::BreakpointOptionsCallbackFunction, baton_sp);

        Error err (reader_sp->Initialize (CommandObjectBreakpointCommandAdd::GenerateBreakpointCommandCallback,
                                          bp_options,                   // baton
                                          eInputReaderGranularityLine,  // token size, to pass to callback function
                                          "DONE",                       // end token
                                          "> ",                         // prompt
                                          true));                       // echo input
        if (err.Success())
        {
            Debugger::GetSharedInstance().PushInputReader (reader_sp);
            result.SetStatus (eReturnStatusSuccessFinishNoResult);
        }
        else
        {
            result.AppendError (err.AsCString());
            result.SetStatus (eReturnStatusFailed);
        }
    }
    else
    {
        result.AppendError("out of memory");
        result.SetStatus (eReturnStatusFailed);
    }

}

size_t
CommandObjectBreakpointCommandAdd::GenerateBreakpointCommandCallback
(
    void *baton, 
    InputReader *reader, 
    lldb::InputReaderAction notification,
    const char *bytes, 
    size_t bytes_len
)
{
    FILE *out_fh = Debugger::GetSharedInstance().GetOutputFileHandle();

    switch (notification)
    {
    case eInputReaderActivate:
        if (out_fh)
        {
            ::fprintf (out_fh, "%s\n", g_reader_instructions);
            if (reader->GetPrompt())
                ::fprintf (out_fh, "%s", reader->GetPrompt());
        }
        break;

    case eInputReaderDeactivate:
        break;

    case eInputReaderReactivate:
        if (out_fh && reader->GetPrompt())
            ::fprintf (out_fh, "%s", reader->GetPrompt());
        break;

    case eInputReaderGotToken:
        if (bytes && bytes_len && baton)
        {
            BreakpointOptions *bp_options = (BreakpointOptions *) baton;
            if (bp_options)
            {
                Baton *bp_options_baton = bp_options->GetBaton();
                if (bp_options_baton)
                    ((BreakpointOptions::CommandData *)bp_options_baton->m_data)->user_source.AppendString (bytes, bytes_len); 
            }
        }
        if (out_fh && !reader->IsDone() && reader->GetPrompt())
            ::fprintf (out_fh, "%s", reader->GetPrompt());
        break;
        
    case eInputReaderDone:
        break;
    }

    return bytes_len;
}


//-------------------------------------------------------------------------
// CommandObjectBreakpointCommandRemove
//-------------------------------------------------------------------------

CommandObjectBreakpointCommandRemove::CommandObjectBreakpointCommandRemove () :
    CommandObject ("remove",
                   "Remove the set of commands from a breakpoint.",
                   "breakpoint command remove <breakpoint-id>")
{
}

CommandObjectBreakpointCommandRemove::~CommandObjectBreakpointCommandRemove ()
{
}

bool
CommandObjectBreakpointCommandRemove::Execute (Args& command,
                                               CommandContext *context,
                                               CommandInterpreter *interpreter,
                                               CommandReturnObject &result)
{
    Target *target = context->GetTarget();

    if (target == NULL)
    {
        result.AppendError ("There is not a current executable; there are no breakpoints from which to remove commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    const BreakpointList &breakpoints = target->GetBreakpointList();
    size_t num_breakpoints = breakpoints.GetSize();

    if (num_breakpoints == 0)
    {
        result.AppendError ("No breakpoints exist to have commands removed");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    if (command.GetArgumentCount() == 0)
    {
        result.AppendError ("No breakpoint specified from which to remove the commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    BreakpointIDList valid_bp_ids;
    CommandObjectMultiwordBreakpoint::VerifyBreakpointIDs (command, target, result, &valid_bp_ids);

    if (result.Succeeded())
    {
        for (int i = 0; i < valid_bp_ids.Size(); ++i)
        {
            BreakpointID cur_bp_id = valid_bp_ids.GetBreakpointIDAtIndex (i);
            if (cur_bp_id.GetBreakpointID() != LLDB_INVALID_BREAK_ID)
            {
                Breakpoint *bp = target->GetBreakpointByID (cur_bp_id.GetBreakpointID()).get();
                if (cur_bp_id.GetLocationID() != LLDB_INVALID_BREAK_ID)
                {
                    BreakpointLocationSP bp_loc_sp (bp->FindLocationByID (cur_bp_id.GetLocationID()));
                    if (bp_loc_sp)
                        bp_loc_sp->ClearCallback();
                    else
                    {
                        result.AppendErrorWithFormat("Invalid breakpoint ID: %u.%u.\n", 
                                                     cur_bp_id.GetBreakpointID(),
                                                     cur_bp_id.GetLocationID());
                        result.SetStatus (eReturnStatusFailed);
                        return false;
                    }
                }
                else
                {
                    bp->ClearCallback();
                }
            }
        }
    }
    return result.Succeeded();
}


//-------------------------------------------------------------------------
// CommandObjectBreakpointCommandList
//-------------------------------------------------------------------------

CommandObjectBreakpointCommandList::CommandObjectBreakpointCommandList () :
    CommandObject ("List",
                   "List the script or set of commands to be executed when the breakpoint is hit.",
                   "breakpoint command list <breakpoint-id>")
{
}

CommandObjectBreakpointCommandList::~CommandObjectBreakpointCommandList ()
{
}

bool
CommandObjectBreakpointCommandList::Execute (Args& command,
                                             CommandContext *context,
                                             CommandInterpreter *interpreter,
                                             CommandReturnObject &result)
{
    Target *target = context->GetTarget();

    if (target == NULL)
    {
        result.AppendError ("There is not a current executable; there are no breakpoints for which to list commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    const BreakpointList &breakpoints = target->GetBreakpointList();
    size_t num_breakpoints = breakpoints.GetSize();

    if (num_breakpoints == 0)
    {
        result.AppendError ("No breakpoints exist for which to list commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    if (command.GetArgumentCount() == 0)
    {
        result.AppendError ("No breakpoint specified for which to list the commands");
        result.SetStatus (eReturnStatusFailed);
        return false;
    }

    BreakpointIDList valid_bp_ids;
    CommandObjectMultiwordBreakpoint::VerifyBreakpointIDs (command, target, result, &valid_bp_ids);

    if (result.Succeeded())
    {
        for (int i = 0; i < valid_bp_ids.Size(); ++i)
        {
            BreakpointID cur_bp_id = valid_bp_ids.GetBreakpointIDAtIndex (i);
            if (cur_bp_id.GetBreakpointID() != LLDB_INVALID_BREAK_ID)
            {
                Breakpoint *bp = target->GetBreakpointByID (cur_bp_id.GetBreakpointID()).get();
                
                if (bp)
                {
                    BreakpointOptions *bp_options = NULL;
                    if (cur_bp_id.GetLocationID() != LLDB_INVALID_BREAK_ID)
                    {
                        BreakpointLocationSP bp_loc_sp(bp->FindLocationByID (cur_bp_id.GetLocationID()));
                        if (bp_loc_sp)
                            bp_options = bp_loc_sp->GetOptionsNoCopy();
                        else
                        {
                            result.AppendErrorWithFormat("Invalid breakpoint ID: %u.%u.\n", 
                                                         cur_bp_id.GetBreakpointID(),
                                                         cur_bp_id.GetLocationID());
                            result.SetStatus (eReturnStatusFailed);
                            return false;
                        }
                    }
                    else
                    {
                        bp_options = bp->GetOptions();
                    }

                    if (bp_options)
                    {
                        StreamString id_str;
                        BreakpointID::GetCanonicalReference (&id_str, cur_bp_id.GetBreakpointID(), cur_bp_id.GetLocationID());
                        Baton *baton = bp_options->GetBaton();
                        if (baton)
                        {
                            result.GetOutputStream().Printf ("Breakpoint %s:\n", id_str.GetData());
                            result.GetOutputStream().IndentMore ();
                            baton->GetDescription(&result.GetOutputStream(), eDescriptionLevelFull);
                            result.GetOutputStream().IndentLess ();
                        }
                        else
                        {
                            result.AppendMessageWithFormat ("Breakpoint %s does not have an associated command.\n", id_str.GetData());
                        }
                    }
                    result.SetStatus (eReturnStatusSuccessFinishResult);
                }
                else
                {
                    result.AppendErrorWithFormat("Invalid breakpoint ID: %u.\n", cur_bp_id.GetBreakpointID());
                    result.SetStatus (eReturnStatusFailed);
                }

            }
        }
    }

    return result.Succeeded();
}

//-------------------------------------------------------------------------
// CommandObjectBreakpointCommand
//-------------------------------------------------------------------------

CommandObjectBreakpointCommand::CommandObjectBreakpointCommand (CommandInterpreter *interpreter) :
    CommandObjectMultiword ("command",
                            "A set of commands for adding, removing and examining bits of code to be executed when the breakpoint is hit (breakpoint 'commmands').",
                            "command <sub-command> [<sub-command-options>] <breakpoint-id>")
{
    bool status;
    CommandObjectSP add_command_object (new CommandObjectBreakpointCommandAdd ());
    CommandObjectSP remove_command_object (new CommandObjectBreakpointCommandRemove ());
    CommandObjectSP list_command_object (new CommandObjectBreakpointCommandList ());

    add_command_object->SetCommandName ("breakpoint command add");
    remove_command_object->SetCommandName ("breakpoint command remove");
    list_command_object->SetCommandName ("breakpoint command list");

    status = LoadSubCommand (add_command_object, "add", interpreter);
    status = LoadSubCommand (remove_command_object, "remove", interpreter);
    status = LoadSubCommand (list_command_object, "list", interpreter);
}


CommandObjectBreakpointCommand::~CommandObjectBreakpointCommand ()
{
}

bool
CommandObjectBreakpointCommand::BreakpointOptionsCallbackFunction 
(
    void *baton, 
    StoppointCallbackContext *context,
    lldb::user_id_t break_id, 
    lldb::user_id_t break_loc_id
)
{
    bool ret_value = true;
    if (baton == NULL)
        return true;
    
    
    BreakpointOptions::CommandData *data = (BreakpointOptions::CommandData *) baton;
    StringList &commands = data->user_source;

    if (commands.GetSize() > 0)
    {
        uint32_t num_commands = commands.GetSize();
        CommandInterpreter &interpreter = Debugger::GetSharedInstance().GetCommandInterpreter();
        CommandReturnObject result;
        ExecutionContext exe_ctx = context->context;
        
        FILE *out_fh = Debugger::GetSharedInstance().GetOutputFileHandle();
        FILE *err_fh = Debugger::GetSharedInstance().GetErrorFileHandle();
            

        uint32_t i;
        for (i = 0; i < num_commands; ++i)
        {
            
            // First time through we use the context from the stoppoint, after that we use whatever
            // has been set by the previous command.
            
            if (!interpreter.HandleCommand (commands.GetStringAtIndex(i), false, result, &exe_ctx))
                break;
                
            // FIXME: This isn't really the right way to do this.  We should be able to peek at the public 
            // to see if there is any new events, but that is racey, since the internal process thread has to run and
            // deliver the event to the public queue before a run will show up.  So for now we check
            // the internal thread state.
            
            lldb::StateType internal_state = exe_ctx.process->GetPrivateState();
            if (internal_state != eStateStopped)
            {
                if (i < num_commands - 1)
                {
                    if (out_fh)
                        ::fprintf (out_fh, "Short-circuiting command execution because target state changed to %s."
                                           " last command: \"%s\"\n", StateAsCString(internal_state),
                                           commands.GetStringAtIndex(i));
                }
                break;
            }
            
            // First time through we use the context from the stoppoint, after that we use whatever
            // has been set by the previous command.
            exe_ctx = Debugger::GetSharedInstance().GetCurrentExecutionContext();

            
            if (out_fh)
                ::fprintf (out_fh, "%s", result.GetErrorStream().GetData());
            if (err_fh)
                ::fprintf (err_fh, "%s", result.GetOutputStream().GetData());
            result.Clear();
            result.SetStatus (eReturnStatusSuccessFinishNoResult);
        }

        if (err_fh && !result.Succeeded() && i < num_commands)
            ::fprintf (err_fh, "Attempt to execute '%s' failed.\n", commands.GetStringAtIndex(i));

        if (out_fh)
            ::fprintf (out_fh, "%s", result.GetErrorStream().GetData());

        if (err_fh)
            ::fprintf (err_fh, "%s", result.GetOutputStream().GetData());        
    }
    return ret_value;
}

