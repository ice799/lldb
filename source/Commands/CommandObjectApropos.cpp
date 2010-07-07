//===-- CommandObjectApropos.cpp ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CommandObjectApropos.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Interpreter/Args.h"
#include "lldb/Interpreter/Options.h"

#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"

using namespace lldb;
using namespace lldb_private;

//-------------------------------------------------------------------------
// CommandObjectApropos
//-------------------------------------------------------------------------

CommandObjectApropos::CommandObjectApropos () :
    CommandObject ("apropos",
                     "Finds a list of debugger commands related to a particular word/subject.",
                     "apropos <search-word>")
{
}

CommandObjectApropos::~CommandObjectApropos()
{
}


bool
CommandObjectApropos::Execute
(
    CommandInterpreter &interpreter,
    Args& args,
    CommandReturnObject &result
)
{
    const int argc = args.GetArgumentCount ();

    if (argc == 1)
    {
        const char *search_word = args.GetArgumentAtIndex(0);
        if ((search_word != NULL)
            && (strlen (search_word) > 0))
        {
            // The bulk of the work must be done inside the Command Interpreter, since the command dictionary
            // is private.
            StringList commands_found;
            StringList commands_help;
            interpreter.FindCommandsForApropos (search_word, commands_found, commands_help);
            if (commands_found.GetSize() == 0)
            {
                result.AppendMessageWithFormat ("No commands found pertaining to '%s'.", search_word);
                result.AppendMessage ("Try 'help' to see a complete list of debugger commands.");
            }
            else
            {
                result.AppendMessageWithFormat ("The following commands may relate to '%s':\n", search_word);
                size_t max_len = 0;

                for (int i = 0; i < commands_found.GetSize(); ++i)
                {
                    int len = strlen (commands_found.GetStringAtIndex (i));
                    if (len > max_len)
                        max_len = len;
                }

                for (int i = 0; i < commands_found.GetSize(); ++i)
                    interpreter.OutputFormattedHelpText (result.GetOutputStream(), 
                                                         commands_found.GetStringAtIndex(i),
                                                         "--", commands_help.
                                                         GetStringAtIndex(i), 
                                                         max_len);

            }
            result.SetStatus (eReturnStatusSuccessFinishNoResult);
        }
        else
        {
            result.AppendError ("'' is not a valid search word.\n");
            result.SetStatus (eReturnStatusFailed);
        }
    }
    else
    {
        result.AppendError ("'apropos' must be called with exactly one argument.\n");
        result.SetStatus (eReturnStatusFailed);
    }

    return result.Succeeded();
}
