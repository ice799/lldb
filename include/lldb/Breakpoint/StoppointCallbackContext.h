//===-- StoppointCallbackContext.h ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_StoppointCallbackContext_h_
#define liblldb_StoppointCallbackContext_h_

#include "lldb/lldb-private.h"
#include "lldb/Target/ExecutionContext.h"

namespace lldb_private {

//----------------------------------------------------------------------
/// @class StoppointCallbackContext StoppointCallbackContext.h "lldb/Breakpoint/StoppointCallbackContext.h"
/// @brief Class holds the information that a breakpoint callback needs to evaluate this stop.
//----------------------------------------------------------------------

//----------------------------------------------------------------------
/// General Outline:
/// When we hit a breakpoint we need to package up whatever information is needed
/// to evaluate breakpoint commands and conditions.  This class is the container of
/// that information.
//----------------------------------------------------------------------

class StoppointCallbackContext
{
public:
    StoppointCallbackContext();

    StoppointCallbackContext(Event *event, Process* process, Thread *thread = NULL, StackFrame * frame = NULL, bool synchronously = false);

    //------------------------------------------------------------------
    /// Clear the object's state.
    ///
    /// Sets the event, process and thread to NULL, and the frame index to an
    /// invalid value.
    //------------------------------------------------------------------
    void
    Clear ();

    //------------------------------------------------------------------
    // Member variables
    //------------------------------------------------------------------
    Event *event;               // This is the event, the callback can modify this to indicate
                                // the meaning of the breakpoint hit
    ExecutionContext exe_ctx;   // This tells us where we have stopped, what thread.
    bool is_synchronous;        // Is the callback being executed synchronously with the breakpoint, 
                                // or asynchronously as the event is retrieved?
};

} // namespace lldb_private

#endif  // liblldb_StoppointCallbackContext_h_
