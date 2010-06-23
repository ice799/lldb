//===-- CommandObjectScript.cpp ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CommandObjectScript.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Interpreter/Args.h"

#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Interpreter/ScriptInterpreter.h"
#include "lldb/Interpreter/ScriptInterpreterPython.h"
#include "lldb/Interpreter/ScriptInterpreterNone.h"

using namespace lldb;
using namespace lldb_private;

//-------------------------------------------------------------------------
// CommandObjectScript
//-------------------------------------------------------------------------

CommandObjectScript::CommandObjectScript (ScriptLanguage script_lang) :
    CommandObject ("script",
                   "Passes an expression to the script interpreter for evaluation and returns the results. Drops user into the interactive interpreter if no expressions are given.",
                   "script [<script-expressions-for-evaluation>]"),
    m_script_lang (script_lang),
    m_interpreter_ap ()
{
}

CommandObjectScript::~CommandObjectScript ()
{
}

bool
CommandObjectScript::ExecuteRawCommandString
(
    CommandInterpreter &interpreter,
    const char *command,
    CommandReturnObject &result
)
{
    ScriptInterpreter *script_interpreter = GetInterpreter (interpreter);

    if (script_interpreter == NULL)
    {
        result.AppendError("no script interpeter");
        result.SetStatus (eReturnStatusFailed);
    }

    if (command == NULL || command[0] == '\0')
        script_interpreter->ExecuteInterpreterLoop (interpreter);
    else
        script_interpreter->ExecuteOneLine (interpreter, command); 
    result.SetStatus (eReturnStatusSuccessFinishNoResult);
    return result.Succeeded();
}

bool
CommandObjectScript::WantsRawCommandString()
{
    return true;
}

bool
CommandObjectScript::Execute
(
    CommandInterpreter &interpreter,
    Args& command,
    CommandReturnObject &result
)
{
    // everything should be handled in ExecuteRawCommandString
    return false;
}


ScriptInterpreter *
CommandObjectScript::GetInterpreter (CommandInterpreter &interpreter)
{
    if (m_interpreter_ap.get() == NULL)
    {
        switch (m_script_lang)
        {
        case eScriptLanguagePython:
            m_interpreter_ap.reset (new ScriptInterpreterPython (interpreter));
            break;

        case eScriptLanguageNone:
            m_interpreter_ap.reset (new ScriptInterpreterNone (interpreter));
            break;
        }
    }
    return m_interpreter_ap.get();
}
