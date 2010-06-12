//===-- Thread.h ------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_Thread_h_
#define liblldb_Thread_h_

#include "lldb/lldb-private.h"
#include "lldb/Host/Mutex.h"
#include "lldb/Core/UserID.h"
#include "lldb/Target/ExecutionContextScope.h"
#include "lldb/Target/StackFrameList.h"

#define LLDB_THREAD_MAX_STOP_EXC_DATA 8

// I forward declare these here so I don't have to #include ThreadPlan, so in turn I
// can use Thread.h in ThreadPlan.h.

namespace lldb_private {

class Thread :
    public UserID,
    public ExecutionContextScope
{
friend class ThreadPlan;
public:
    //----------------------------------------------------------------------
    // StopInfo
    //
    // Describes the reason the thread it was created with stopped.
    //----------------------------------------------------------------------
    class StopInfo
    {
    public:
        StopInfo(Thread *thread = NULL);

        ~StopInfo();

        // Clear clears the stop reason, but it does not clear the thread this
        // StopInfo is tied to.
        void
        Clear();

        lldb::StopReason
        GetStopReason() const;

        void
        SetThread (Thread *thread);

        Thread *
        GetThread ();

        void
        SetStopReasonWithBreakpointSiteID (lldb::user_id_t break_id);

        void
        SetStopReasonWithWatchpointID (lldb::user_id_t watch_id);

        void
        SetStopReasonWithSignal (int signo);

        void
        SetStopReasonToTrace ();

        void
        SetStopReasonWithException (uint32_t exc_type, size_t exc_data_count);

        void
        SetStopReasonWithPlan (lldb::ThreadPlanSP &plan);

        void
        SetStopReasonToNone ();

        const char *
        GetStopDescription() const;

        void
        SetStopDescription(const char *desc);

        lldb::user_id_t
        GetBreakpointSiteID() const;

        lldb::user_id_t
        GetWatchpointID() const;

        int
        GetSignal() const;

        lldb::user_id_t
        GetPlanID () const;

        uint32_t
        GetExceptionType() const;

        size_t
        GetExceptionDataCount() const;

        lldb::addr_t
        GetExceptionDataAtIndex (uint32_t idx) const;

        bool
        SetExceptionDataAtIndex (uint32_t idx, lldb::addr_t data);

        void
        Dump (Stream *s) const;

    protected:
        lldb::StopReason m_reason;
        //--------------------------------------------------------------
        // For eStopReasonPlan the completed plan is stored in this shared pointer.
        //--------------------------------------------------------------
        lldb::ThreadPlanSP m_completed_plan_sp;
        Thread *m_thread;
        char m_description[256];
        union
        {
            //--------------------------------------------------------------
            // eStopReasonBreakpoint
            //--------------------------------------------------------------
            struct
            {
                lldb::user_id_t bp_site_id;
            } breakpoint;
            //--------------------------------------------------------------
            // eStopReasonWatchpoint
            //--------------------------------------------------------------
            struct
            {
                lldb::user_id_t watch_id;
            } watchpoint;
            //--------------------------------------------------------------
            // eStopReasonSignal
            //--------------------------------------------------------------
            struct
            {
                int signo;
            } signal;
            //--------------------------------------------------------------
            // eStopReasonException
            //--------------------------------------------------------------
            struct
            {
                uint32_t type;
                size_t data_count;
                lldb::addr_t data[LLDB_THREAD_MAX_STOP_EXC_DATA];
            } exception;
        } m_details;
    };

    class RegisterCheckpoint
    {
    public:

        RegisterCheckpoint() :
            m_stack_id (),
            m_data_sp ()
        {
        }

        RegisterCheckpoint (const StackID &stack_id) :
            m_stack_id (stack_id),
            m_data_sp ()
        {
        }

        ~RegisterCheckpoint()
        {
        }

        const StackID &
        GetStackID()
        {
            return m_stack_id;
        }

        void
        SetStackID (const StackID &stack_id)
        {
            m_stack_id = stack_id;
        }

        lldb::DataBufferSP &
        GetData()
        {
            return m_data_sp;
        }

        const lldb::DataBufferSP &
        GetData() const
        {
            return m_data_sp;
        }

    protected:
        StackID m_stack_id;
        lldb::DataBufferSP m_data_sp;
    };

    Thread (Process &process, lldb::tid_t tid);
    virtual ~Thread();

    Process &
    GetProcess() { return m_process; }

    const Process &
    GetProcess() const { return m_process; }

    int
    GetResumeSignal () const;

    void
    SetResumeSignal (int signal);

    lldb::StateType
    GetState() const;

    lldb::ThreadSP
    GetSP ();

    void
    SetState (lldb::StateType state);

    lldb::StateType
    GetResumeState () const;

    void
    SetResumeState (lldb::StateType state);

    // This function is called on all the threads before "WillResume" in case
    // a thread needs to change its state before the ThreadList polls all the
    // threads to figure out which ones actually will get to run and how.
    void
    SetupForResume ();
    
    // Override this to do platform specific tasks before resume, but always
    // call the Thread::WillResume at the end of your work.

    virtual bool
    WillResume (lldb::StateType resume_state);

    // This clears generic thread state after a resume.  If you subclass this,
    // be sure to call it.
    virtual void
    DidResume ();

    virtual void
    RefreshStateAfterStop() = 0;

    void
    WillStop ();

    bool
    ShouldStop (Event *event_ptr);

    lldb::Vote
    ShouldReportStop (Event *event_ptr);

    lldb::Vote
    ShouldReportRun (Event *event_ptr);

    bool
    GetStopInfo (StopInfo *stop_info);

    bool
    ThreadStoppedForAReason ();

    virtual const char *
    GetInfo () = 0;

    virtual const char *
    GetName ()
    {
        return NULL;
    }

    virtual const char *
    GetQueueName ()
    {
        return NULL;
    }

    virtual uint32_t
    GetStackFrameCount() = 0;

    virtual lldb::StackFrameSP
    GetStackFrameAtIndex (uint32_t idx) = 0;

    lldb::StackFrameSP
    GetCurrentFrame ();

    uint32_t
    SetCurrentFrame (lldb_private::StackFrame *frame);

    void
    SetCurrentFrameByIndex (uint32_t frame_idx);

    virtual RegisterContext *
    GetRegisterContext () = 0;

    virtual bool
    SaveFrameZeroState (RegisterCheckpoint &checkpoint) = 0;

    virtual bool
    RestoreSaveFrameZero (const RegisterCheckpoint &checkpoint) = 0;

    virtual RegisterContext *
    CreateRegisterContextForFrame (StackFrame *frame) = 0;
    
    virtual void
    ClearStackFrames ()
    {
        m_frames.Clear();
    }

    void
    DumpInfo (Stream &strm,
              bool show_stop_reason,
              bool show_name,
              bool show_queue,
              uint32_t frame_idx);// = UINT32_MAX);

    //------------------------------------------------------------------
    // Thread Plan Providers:
    // This section provides the basic thread plans that the Process control
    // machinery uses to run the target.  ThreadPlan.h provides more details on
    // how this mechanism works.
    // The thread provides accessors to a set of plans that perform basic operations.
    // The idea is that particular Platform plugins can override these methods to
    // provide the implementation of these basic operations appropriate to their
    // environment.
    //------------------------------------------------------------------

    //------------------------------------------------------------------
    /// Queues the base plan for a thread.
    /// The version returned by Process does some things that are useful,
    /// like handle breakpoints and signals, so if you return a plugin specific
    /// one you probably want to call through to the Process one for anything
    /// your plugin doesn't explicitly handle.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueFundamentalPlan (bool abort_other_plans);

    //------------------------------------------------------------------
    /// Queues the plan used to step over a breakpoint at the current PC of \a thread.
    /// The default version returned by Process handles trap based breakpoints, and
    /// will disable the breakpoint, single step over it, then re-enable it.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForStepOverBreakpointPlan (bool abort_other_plans);

    //------------------------------------------------------------------
    /// Queues the plan used to step one instruction from the current PC of \a thread.
    ///
    /// @param[in] step_over
    ///    \b true if we step over calls to functions, false if we step in.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForStepSingleInstruction (bool step_over,
                                             bool abort_other_plans,
                                             bool stop_other_threads);

    //------------------------------------------------------------------
    /// Queues the plan used to step through an address range, stepping into or over
    /// function calls depending on the value of StepType.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] type
    ///    Type of step to do, only eStepTypeInto and eStepTypeOver are supported by this plan.
    ///
    /// @param[in] range
    ///    The address range to step through.
    ///
    /// @param[in] addr_context
    ///    When dealing with stepping through inlined functions the current PC is not enough information to know
    ///    what "step" means.  For instance a series of nested inline functions might start at the same address.
    //     The \a addr_context provides the current symbol context the step
    ///    is supposed to be out of.
    //   FIXME: Currently unused.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForStepRange (bool abort_other_plans,
                                 lldb::StepType type,
                                 const AddressRange &range,
                                 const SymbolContext &addr_context,
                                 lldb::RunMode stop_other_threads,
                                 bool avoid_code_without_debug_info);

    //------------------------------------------------------------------
    /// Queue the plan used to step out of the function at the current PC of
    /// \a thread.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] addr_context
    ///    When dealing with stepping through inlined functions the current PC is not enough information to know
    ///    what "step" means.  For instance a series of nested inline functions might start at the same address.
    //     The \a addr_context provides the current symbol context the step
    ///    is supposed to be out of.
    //   FIXME: Currently unused.
    ///
    /// @param[in] first_insn
    ///     \b true if this is the first instruction of a function.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @param[in] stop_vote
    /// @param[in] run_vote
    ///    See standard meanings for the stop & run votes in ThreadPlan.h.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForStepOut (bool abort_other_plans,
                               SymbolContext *addr_context,
                               bool first_insn,
                               bool stop_other_threads,
                               lldb::Vote stop_vote = lldb::eVoteYes,
                               lldb::Vote run_vote = lldb::eVoteNoOpinion);

    //------------------------------------------------------------------
    /// Gets the plan used to step through the code that steps from a function
    /// call site at the current PC into the actual function call.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForStepThrough (bool abort_other_plans,
                                   bool stop_other_threads);

    //------------------------------------------------------------------
    /// Gets the plan used to continue from the current PC.
    /// This is a simple plan, mostly useful as a backstop when you are continuing
    /// for some particular purpose.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @param[in] stop_vote
    /// @param[in] run_vote
    ///    See standard meanings for the stop & run votes in ThreadPlan.h.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForContinue (bool abort_other_plans,
                                bool stop_other_threads,
                                    lldb::Vote stop_vote,
                                    lldb::Vote run_vote = lldb::eVoteNoOpinion,
                                    bool immediate = false);
    //------------------------------------------------------------------
    /// Gets the plan used to continue from the current PC.
    /// This is a simple plan, mostly useful as a backstop when you are continuing
    /// for some particular purpose.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @param[in] target_addr
    ///    The address to which we're running.
    ///
    /// @param[in] stop_other_threads
    ///    \b true if we will stop other threads while we single step this one.
    ///
    /// @return
    ///     A pointer to the newly queued thread plan, or NULL if the plan could not be queued.
    //------------------------------------------------------------------
    virtual ThreadPlan *
    QueueThreadPlanForRunToAddress (bool abort_other_plans,
                                    Address &target_addr,
                                    bool stop_other_threads);

    virtual ThreadPlan *
    QueueThreadPlanForStepUntil (bool abort_other_plans,
                               lldb::addr_t *address_list,
                               size_t num_addresses,
                               bool stop_others);

    virtual ThreadPlan *
    QueueThreadPlanForCallFunction (bool abort_other_plans,
                                    Address& function,
                                    lldb::addr_t arg,
                                    bool stop_other_threads,
                                    bool discard_on_error = false);
    
    virtual ThreadPlan *
    QueueThreadPlanForCallFunction (bool abort_other_plans,
                                    Address& function,
                                    ValueList &args,
                                    bool stop_other_threads,
                                    bool discard_on_error = false);
                                            
    //------------------------------------------------------------------
    // Thread Plan accessors:
    //------------------------------------------------------------------

    //------------------------------------------------------------------
    /// Gets the plan which will execute next on the plan stack.
    ///
    /// @return
    ///     A pointer to the next executed plan.
    //------------------------------------------------------------------
    ThreadPlan *
    GetCurrentPlan ();

    //------------------------------------------------------------------
    /// Gets the inner-most plan that was popped off the plan stack in the
    /// most recent stop.  Useful for printing the stop reason accurately.
    ///
    /// @return
    ///     A pointer to the last completed plan.
    //------------------------------------------------------------------
    lldb::ThreadPlanSP
    GetCompletedPlan ();

    //------------------------------------------------------------------
    ///  Checks whether the given plan is in the completed plans for this
    ///  stop.
    ///
    /// @param[in] plan
    ///     Pointer to the plan you're checking.
    ///
    /// @return
    ///     Returns true if the input plan is in the completed plan stack,
    ///     false otherwise.
    //------------------------------------------------------------------
    bool
    IsThreadPlanDone (ThreadPlan *plan);

    //------------------------------------------------------------------
    ///  Checks whether the given plan is in the discarded plans for this
    ///  stop.
    ///
    /// @param[in] plan
    ///     Pointer to the plan you're checking.
    ///
    /// @return
    ///     Returns true if the input plan is in the discarded plan stack,
    ///     false otherwise.
    //------------------------------------------------------------------
    bool
    WasThreadPlanDiscarded (ThreadPlan *plan);

    //------------------------------------------------------------------
    /// Queues a generic thread plan.
    ///
    /// @param[in] plan_sp
    ///    The plan to queue.
    ///
    /// @param[in] abort_other_plans
    ///    \b true if we discard the currently queued plans and replace them with this one.
    ///    Otherwise this plan will go on the end of the plan stack.
    ///
    /// @return
    ///     A pointer to the last completed plan.
    //------------------------------------------------------------------
    void
    QueueThreadPlan (lldb::ThreadPlanSP &plan_sp, bool abort_other_plans);


    //------------------------------------------------------------------
    /// Discards the plans queued on the plan stack of the current thread.  This is
    /// arbitrated by the "Master" ThreadPlans, using the "OkayToDiscard" call.
    //  But if \a force is true, all thread plans are discarded.
    //------------------------------------------------------------------
    void
    DiscardThreadPlans (bool force);

    //------------------------------------------------------------------
    /// Prints the current plan stack.
    ///
    /// @param[in] s
    ///    The stream to which to dump the plan stack info.
    ///
    //------------------------------------------------------------------
    void
    DumpThreadPlans (Stream *s) const;

    // Get the thread index ID. The index ID that is guaranteed to not be
    // re-used by a process. They start at 1 and increase with each new thread.
    // This allows easy command line access by a unique ID that is easier to
    // type than the actual system thread ID.
    uint32_t
    GetIndexID () const;

    //------------------------------------------------------------------
    // lldb::ExecutionContextScope pure virtual functions
    //------------------------------------------------------------------
    virtual Target *
    CalculateTarget ();

    virtual Process *
    CalculateProcess ();

    virtual Thread *
    CalculateThread ();

    virtual StackFrame *
    CalculateStackFrame ();

    virtual void
    Calculate (ExecutionContext &exe_ctx);

protected:
    void
    PushPlan (lldb::ThreadPlanSP &plan_sp);

    void
    PopPlan ();

    void
    DiscardPlan ();

    ThreadPlan *GetPreviousPlan (ThreadPlan *plan);

    virtual bool
    GetRawStopReason (StopInfo *stop_info) = 0;

    typedef std::vector<lldb::ThreadPlanSP> plan_stack;

    //------------------------------------------------------------------
    // Classes that inherit from Process can see and modify these
    //------------------------------------------------------------------
    Process &           m_process;          ///< The process that owns this thread.
    const uint32_t      m_index_id;         ///< A unique 1 based index assigned to each thread for easy UI/command line access.
    lldb::RegisterContextSP   m_reg_context_sp;   ///< The register context for this thread's current register state.
    lldb::StateType     m_state;            ///< The state of our process.
    plan_stack          m_plan_stack;       ///< The stack of plans this thread is executing.
    plan_stack          m_immediate_plan_stack; ///< The plans that need to get executed before any other work gets done.
    plan_stack          m_completed_plan_stack;  ///< Plans that have been completed by this stop.  They get deleted when the thread resumes.
    plan_stack          m_discarded_plan_stack;  ///< Plans that have been discarded by this stop.  They get deleted when the thread resumes.
    mutable Mutex m_state_mutex;      ///< Multithreaded protection for m_state.
    StackFrameList      m_frames;           ///< The stack frames that get lazily populated after a thread stops.
    uint32_t            m_current_frame_idx;///< The current frame for this thread
    int                 m_resume_signal;    ///< The signal that should be used when continuing this thread.
    lldb::StateType     m_resume_state;     ///< The state that indicates what this thread should do when the process is resumed.
private:
    //------------------------------------------------------------------
    // For Thread only
    //------------------------------------------------------------------
    DISALLOW_COPY_AND_ASSIGN (Thread);

};

} // namespace lldb_private

#endif  // liblldb_Thread_h_
