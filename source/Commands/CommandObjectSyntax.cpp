//===-- CommandObjectSyntax.cpp ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CommandObjectSyntax.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Interpreter/Args.h"
#include "lldb/Interpreter/Options.h"

#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Interpreter/CommandObjectMultiword.h"

using namespace lldb;
using namespace lldb_private;

//-------------------------------------------------------------------------
// CommandObjectSyntax
//-------------------------------------------------------------------------

CommandObjectSyntax::CommandObjectSyntax () :
    CommandObject ("syntax",
                     "Shows the correct syntax for a given debugger command.",
                     "syntax <command>")
{
}

CommandObjectSyntax::~CommandObjectSyntax()
{
}


bool
CommandObjectSyntax::OldExecute
(
    Args& command,
    CommandContext *context,
    CommandInterpreter *interpreter,
    CommandReturnObject &result
)
{
    CommandObject *cmd_obj;

    if (command.GetArgumentCount() != 0)
    {
        cmd_obj = interpreter->GetCommandObject(command.GetArgumentAtIndex(0));
        if (cmd_obj)
        {
            Stream &output_strm = result.GetOutputStream();
            if (cmd_obj->GetOptions() != NULL)
            {
                output_strm.Printf ("\nSyntax: %s\n", cmd_obj->GetSyntax());
                //cmd_obj->GetOptions()->GenerateOptionUsage (output_strm, cmd_obj);
                output_strm.Printf ("(Try 'help %s' for more information on command options syntax.)\n",
                                    cmd_obj->GetCommandName());
                result.SetStatus (eReturnStatusSuccessFinishNoResult);
            }
            else
            {
                output_strm.Printf ("\nSyntax: %s\n", cmd_obj->GetSyntax());
                result.SetStatus (eReturnStatusSuccessFinishNoResult);
            }
        }
        else
        {
            result.AppendErrorWithFormat ("'%s' is not a known command.\n", command.GetArgumentAtIndex(0));
            result.AppendError ("Try 'help' to see a current list of commands.");
            result.SetStatus (eReturnStatusFailed);
        }
    }
    else
    {
        result.AppendError ("Must call 'syntax' with a valid command.");
        result.SetStatus (eReturnStatusFailed);
    }
    return result.Succeeded();
}

bool
CommandObjectSyntax::Execute (Args &command, CommandContext *context, CommandInterpreter *interpreter, 
                              CommandReturnObject &result)
{
    CommandObject::CommandMap::iterator pos;
    CommandObject *cmd_obj;
    const int argc = command.GetArgumentCount();

    if (argc > 0)
    {
        cmd_obj = interpreter->GetCommandObject (command.GetArgumentAtIndex(0));
        bool all_okay = true;
        for (int i = 1; i < argc; ++i)
        {
            std::string sub_command = command.GetArgumentAtIndex (i);
            if (! cmd_obj->IsMultiwordObject())
                all_okay = false;
            else
            {
                pos = ((CommandObjectMultiword *) cmd_obj)->m_subcommand_dict.find (sub_command);
                if (pos != ((CommandObjectMultiword *) cmd_obj)->m_subcommand_dict.end())
                    cmd_obj = pos->second.get();
                else
                    all_okay = false;
            }
        }
        
        if (all_okay && (cmd_obj != NULL))
        {
            Stream &output_strm = result.GetOutputStream();
            if (cmd_obj->GetOptions() != NULL)
            {
                output_strm.Printf ("\nSyntax: %s\n", cmd_obj->GetSyntax());
                //cmd_obj->GetOptions()->GenerateOptionUsage (output_strm, cmd_obj);
                output_strm.Printf ("(Try 'help %s' for more information on command options syntax.)\n",
                                    cmd_obj->GetCommandName());
                result.SetStatus (eReturnStatusSuccessFinishNoResult);
            }
            else
            {
                output_strm.Printf ("\nSyntax: %s\n", cmd_obj->GetSyntax());
                result.SetStatus (eReturnStatusSuccessFinishNoResult);
            }
        }
        else
        {
            std::string cmd_string;
            command.GetCommandString (cmd_string);
            result.AppendErrorWithFormat ("'%s' is not a known command.\n", cmd_string.c_str());
            result.AppendError ("Try 'help' to see a current list of commands.");
            result.SetStatus (eReturnStatusFailed);
        }
    }
    else
    {
        result.AppendError ("Must call 'syntax' with a valid command.");
        result.SetStatus (eReturnStatusFailed);
    }

    return result.Succeeded();
}
