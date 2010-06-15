//===-- CommandObjectFrame.cpp ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CommandObjectFrame.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Interpreter/Args.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Timer.h"
#include "lldb/Interpreter/CommandContext.h"
#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Thread.h"

#include "CommandObjectThread.h"

using namespace lldb;
using namespace lldb_private;

#pragma mark CommandObjectFrameInfo

//-------------------------------------------------------------------------
// CommandObjectFrameInfo
//-------------------------------------------------------------------------

class CommandObjectFrameInfo : public CommandObject
{
public:

    CommandObjectFrameInfo () :
    CommandObject ("frame info",
                   "Lists information about the currently selected frame in the current thread.",
                   "frame info",
                   eFlagProcessMustBeLaunched | eFlagProcessMustBePaused)
    {
    }

    ~CommandObjectFrameInfo ()
    {
    }

    bool
    Execute (Args& command,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        ExecutionContext exe_ctx(context->GetExecutionContext());
        if (exe_ctx.frame)
        {
            exe_ctx.frame->Dump (&result.GetOutputStream(), true);
            result.GetOutputStream().EOL();
            result.SetStatus (eReturnStatusSuccessFinishResult);
        }
        else
        {
            result.AppendError ("no current frame");
            result.SetStatus (eReturnStatusFailed);
        }
        return result.Succeeded();
    }
};

#pragma mark CommandObjectFrameSelect

//-------------------------------------------------------------------------
// CommandObjectFrameSelect
//-------------------------------------------------------------------------

class CommandObjectFrameSelect : public CommandObject
{
public:

    CommandObjectFrameSelect () :
    CommandObject ("frame select",
                   "Select the current frame by index in the current thread.",
                   "frame select <frame-index>",
                   eFlagProcessMustBeLaunched | eFlagProcessMustBePaused)
    {
    }

    ~CommandObjectFrameSelect ()
    {
    }

    bool
    Execute (Args& command,
             CommandContext *context,
             CommandInterpreter *interpreter,
             CommandReturnObject &result)
    {
        ExecutionContext exe_ctx (context->GetExecutionContext());
        if (exe_ctx.thread)
        {
            if (command.GetArgumentCount() == 1)
            {
                const char *frame_idx_cstr = command.GetArgumentAtIndex(0);

                const uint32_t num_frames = exe_ctx.thread->GetStackFrameCount();
                const uint32_t frame_idx = Args::StringToUInt32 (frame_idx_cstr, UINT32_MAX, 0);
                if (frame_idx < num_frames)
                {
                    exe_ctx.thread->SetCurrentFrameByIndex (frame_idx);
                    exe_ctx.frame = exe_ctx.thread->GetCurrentFrame ().get();

                    if (exe_ctx.frame)
                    {
                        if (DisplayFrameForExecutionContext (exe_ctx.thread,
                                                             exe_ctx.frame,
                                                             interpreter,
                                                             result.GetOutputStream(),
                                                             true,
                                                             true,
                                                             3,
                                                             3))
                        {
                            result.SetStatus (eReturnStatusSuccessFinishResult);
                            return result.Succeeded();
                        }
                    }
                }
                if (frame_idx == UINT32_MAX)
                    result.AppendErrorWithFormat ("Invalid frame index: %s.\n", frame_idx_cstr);
                else
                    result.AppendErrorWithFormat ("Frame index (%u) out of range.\n", frame_idx);
            }
            else
            {
                result.AppendError ("invalid arguments");
                result.AppendErrorWithFormat ("Usage: %s\n", m_cmd_syntax.c_str());
            }
        }
        else
        {
            result.AppendError ("no current thread");
        }
        result.SetStatus (eReturnStatusFailed);
        return false;
    }
};

#pragma mark CommandObjectMultiwordFrame

//-------------------------------------------------------------------------
// CommandObjectMultiwordFrame
//-------------------------------------------------------------------------

CommandObjectMultiwordFrame::CommandObjectMultiwordFrame (CommandInterpreter *interpreter) :
    CommandObjectMultiword ("frame",
                            "A set of commands for operating on the current thread's frames.",
                            "frame <subcommand> [<subcommand-options>]")
{
    LoadSubCommand (CommandObjectSP (new CommandObjectFrameInfo ()), "info", interpreter);
    LoadSubCommand (CommandObjectSP (new CommandObjectFrameSelect ()), "select", interpreter);
}

CommandObjectMultiwordFrame::~CommandObjectMultiwordFrame ()
{
}

