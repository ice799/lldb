//===-- ScriptInterpreterNone.h ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_ScriptInterpreterNone_h_
#define liblldb_ScriptInterpreterNone_h_

#include "lldb/Interpreter/ScriptInterpreter.h"

namespace lldb_private {

class ScriptInterpreterNone : public ScriptInterpreter
{
public:

    ScriptInterpreterNone (CommandInterpreter &interpreter);

    ~ScriptInterpreterNone ();

    virtual void
    ExecuteOneLine (CommandInterpreter &interpreter, const char *command);

    virtual void
    ExecuteInterpreterLoop (CommandInterpreter &interpreter);

};

} // namespace lldb_private

#endif // #ifndef liblldb_ScriptInterpreterNone_h_
