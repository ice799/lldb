//===-- ThreadMacOSX.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#include "ThreadMacOSX.h"

#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/DataExtractor.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

#include "ProcessMacOSX.h"
#include "ProcessMacOSXLog.h"
#include "MachThreadContext.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Breakpoint/WatchpointLocation.h"
#include "lldb/Core/StreamString.h"

using namespace lldb;
using namespace lldb_private;

//----------------------------------------------------------------------
// Thread Registers
//----------------------------------------------------------------------

ThreadMacOSX::ThreadMacOSX (ProcessMacOSX &process, lldb::tid_t tid) :
    Thread(process, tid),
    m_fp_pc_pairs(),
    m_basic_info(),
    m_suspend_count(0),
    m_stop_exception(),
    m_context()
{
    ProcessMacOSX::CreateArchCalback create_arch_callback = process.GetArchCreateCallback();
    assert(create_arch_callback != NULL);
    m_context.reset(create_arch_callback(process.GetArchSpec(), *this));
    assert(m_context.get() != NULL);
    m_context->InitializeInstance();
    ::bzero (&m_basic_info, sizeof (m_basic_info));
    ::bzero (&m_ident_info, sizeof (m_ident_info));
    ::bzero (&m_proc_threadinfo, sizeof (m_proc_threadinfo));
    ProcessMacOSXLog::LogIf(PD_LOG_THREAD | PD_LOG_VERBOSE, "ThreadMacOSX::ThreadMacOSX ( pid = %i, tid = 0x%4.4x, )", m_process.GetID(), GetID());
}

ThreadMacOSX::~ThreadMacOSX ()
{
}

#if defined (__i386__) || defined (__x86_64__)
    #define MACH_SOFTWARE_BREAKPOINT_DATA_0 EXC_I386_BPT
    #define MACH_TRAP_DATA_0 EXC_I386_SGL
#elif defined (__powerpc__) || defined (__ppc__) || defined (__ppc64__)
    #define MACH_SOFTWARE_BREAKPOINT_DATA_0 EXC_PPC_BREAKPOINT

#elif defined (__arm__)
    #define MACH_SOFTWARE_BREAKPOINT_DATA_0 EXC_ARM_BREAKPOINT
#endif


bool
ThreadMacOSX::GetRawStopReason (Thread::StopInfo *stop_info )
{
    stop_info->SetThread(this);

    bool success = GetStopException().GetStopInfo(stop_info);


#if defined (MACH_SOFTWARE_BREAKPOINT_DATA_0) || defined (MACH_TRAP_DATA_0)
    if (stop_info->GetStopReason() == eStopReasonException)
    {
        if (stop_info->GetExceptionType() == EXC_BREAKPOINT && stop_info->GetExceptionDataCount() == 2)
        {
            const lldb::addr_t data_0 = stop_info->GetExceptionDataAtIndex(0);
#if defined (MACH_SOFTWARE_BREAKPOINT_DATA_0)
            if (data_0 == MACH_SOFTWARE_BREAKPOINT_DATA_0)
            {
                lldb::addr_t pc = GetRegisterContext()->GetPC();
                lldb::user_id_t break_id = m_process.GetBreakpointSiteList().FindIDByAddress(pc);
                if (break_id != LLDB_INVALID_BREAK_ID)
                {
                    stop_info->Clear ();
                    stop_info->SetStopReasonWithBreakpointSiteID (break_id);
                    return success;
                }
            }
#endif
#if defined (MACH_TRAP_DATA_0)
            if (data_0 == MACH_TRAP_DATA_0)
            {
                stop_info->Clear ();
                stop_info->SetStopReasonToTrace ();
                return success;
            }
#endif
        }
    }
#endif

    if (stop_info->GetStopReason() == eStopReasonException)
    {
        if (stop_info->GetExceptionType() == EXC_SOFTWARE &&
            stop_info->GetExceptionDataCount() == 2 &&
            stop_info->GetExceptionDataAtIndex(0) == EXC_SOFT_SIGNAL)
        {
            int signo = stop_info->GetExceptionDataAtIndex(1);
            stop_info->Clear ();
            stop_info->SetStopReasonWithSignal (signo);
        }
    }
    else
    {
        stop_info->SetStopReasonToNone();
    }

    return success;
}

const char *
ThreadMacOSX::GetInfo ()
{
    return GetBasicInfoAsString();
}

bool
ThreadMacOSX::GetIdentifierInfo ()
{
#ifdef THREAD_IDENTIFIER_INFO_COUNT
    if (m_ident_info.thread_id == 0)
    {
        mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
        return ::thread_info (GetID(), THREAD_IDENTIFIER_INFO, (thread_info_t) &m_ident_info, &count) == KERN_SUCCESS;
    }
#else
    //m_error.SetErrorString("Thread_info doesn't support THREAD_IDENTIFIER_INFO.");
#endif

    return false;
}

const char *
ThreadMacOSX::GetDispatchQueueName()
{
    if (GetIdentifierInfo ())
    {
        if (m_ident_info.dispatch_qaddr == 0)
            return NULL;

        uint8_t memory_buffer[8];
        DataExtractor data(memory_buffer, sizeof(memory_buffer), m_process.GetByteOrder(), m_process.GetAddressByteSize());
        ModuleSP module_sp(m_process.GetTarget().GetImages().FindFirstModuleForFileSpec (FileSpec("libSystem.B.dylib")));
        if (module_sp.get() == NULL)
            return NULL;

        lldb::addr_t dispatch_queue_offsets_addr = LLDB_INVALID_ADDRESS;
        const Symbol *dispatch_queue_offsets_symbol = module_sp->FindFirstSymbolWithNameAndType (ConstString("dispatch_queue_offsets"), eSymbolTypeData);
        if (dispatch_queue_offsets_symbol)
            dispatch_queue_offsets_addr = dispatch_queue_offsets_symbol->GetValue().GetLoadAddress(&GetProcess());

        if (dispatch_queue_offsets_addr == LLDB_INVALID_ADDRESS)
            return NULL;

        // Excerpt from src/queue_private.h
        struct dispatch_queue_offsets_s
        {
            uint16_t dqo_version;
            uint16_t dqo_label;
            uint16_t dqo_label_size;
        } dispatch_queue_offsets;

        Error error;
        if (m_process.ReadMemory (dispatch_queue_offsets_addr, memory_buffer, sizeof(dispatch_queue_offsets), error) == sizeof(dispatch_queue_offsets))
        {
            uint32_t data_offset = 0;
            if (data.GetU16(&data_offset, &dispatch_queue_offsets.dqo_version, sizeof(dispatch_queue_offsets)/sizeof(uint16_t)))
            {
                if (m_process.ReadMemory (m_ident_info.dispatch_qaddr, &memory_buffer, data.GetAddressByteSize(), error) == data.GetAddressByteSize())
                {
                    data_offset = 0;
                    lldb::addr_t queue_addr = data.GetAddress(&data_offset);
                    lldb::addr_t label_addr = queue_addr + dispatch_queue_offsets.dqo_label;
                    const size_t chunk_size = 32;
                    uint32_t label_pos = 0;
                    m_dispatch_queue_name.resize(chunk_size, '\0');
                    while (1)
                    {
                        size_t bytes_read = m_process.ReadMemory (label_addr + label_pos, &m_dispatch_queue_name[label_pos], chunk_size, error);

                        if (bytes_read <= 0)
                            break;

                        if (m_dispatch_queue_name.find('\0', label_pos) != std::string::npos)
                            break;
                        label_pos += bytes_read;
                    }
                    m_dispatch_queue_name.erase(m_dispatch_queue_name.find('\0'));
                }
            }
        }
    }

    if (m_dispatch_queue_name.empty())
        return NULL;
    return m_dispatch_queue_name.c_str();
}

const char *
ThreadMacOSX::GetName ()
{
    if (GetIdentifierInfo ())
        ::proc_pidinfo (m_process.GetID(), PROC_PIDTHREADINFO, m_ident_info.thread_handle, &m_proc_threadinfo, sizeof (m_proc_threadinfo));

    // No thread name, lets return the queue name instead
    if (m_proc_threadinfo.pth_name[0] == '\0')
        return GetDispatchQueueName();

    // Return the thread name if there was one
    if (m_proc_threadinfo.pth_name[0])
        return m_proc_threadinfo.pth_name;
    return NULL;
}

bool
ThreadMacOSX::WillResume (StateType resume_state)
{
    ThreadWillResume(resume_state);
    Thread::WillResume(resume_state);
    return true;
}

void
ThreadMacOSX::RefreshStateAfterStop()
{
    // Invalidate all registers in our register context
    GetRegisterContext()->Invalidate();

    m_context->RefreshStateAfterStop();

    // We may have suspended this thread so the primary thread could step
    // without worrying about race conditions, so lets restore our suspend
    // count.
    RestoreSuspendCount();

    // Update the basic information for a thread for suspend count reasons.
    ThreadMacOSX::GetBasicInfo(GetID(), &m_basic_info);
    m_suspend_count = m_basic_info.suspend_count;
    m_basic_info_string.clear();
}

uint32_t
ThreadMacOSX::GetStackFrameCount()
{
    if (m_fp_pc_pairs.empty())
        GetStackFrameData(m_fp_pc_pairs);
    return m_fp_pc_pairs.size();
}

// Make sure that GetStackFrameAtIndex() does NOT call GetStackFrameCount() when
// getting the stack frame at index zero! This way GetStackFrameCount() (via
// GetStackFRameData()) can call this function to get the first frame in order
// to provide the first frame to a lower call for efficiency sake (avoid
// redundant lookups in the frame symbol context).
lldb::StackFrameSP
ThreadMacOSX::GetStackFrameAtIndex (uint32_t idx)
{
    StackFrameSP frame_sp(m_frames.GetFrameAtIndex(idx));

    if (frame_sp)
        return frame_sp;

    // Don't try and fetch a frame while process is running
    // Calling IsRunning isn't right here, because IsRunning reads the Public
    // state but we need to be able to read the stack frames in the ShouldStop
    // methods, which happen before the Public state has been updated.
//    if (m_process.IsRunning())
//        return frame_sp;

    // Special case the first frame (idx == 0) so that we don't need to
    // know how many stack frames there are to get it. If we need any other
    // frames, then we do need to know if "idx" is a valid index.
    if (idx == 0)
    {
        // If this is the first frame, we want to share the thread register
        // context with the stack frame at index zero.
        GetRegisterContext();
        assert (m_reg_context_sp.get());
        frame_sp.reset (new StackFrame (idx, *this, m_reg_context_sp, m_reg_context_sp->GetFP(), m_reg_context_sp->GetPC()));
    }
    else if (idx < GetStackFrameCount())
    {
        assert (idx < m_fp_pc_pairs.size());
        frame_sp.reset (new StackFrame (idx, *this, m_fp_pc_pairs[idx].first, m_fp_pc_pairs[idx].second));
    }
    m_frames.SetFrameAtIndex(idx, frame_sp);
    return frame_sp;
}

void
ThreadMacOSX::ClearStackFrames ()
{
    m_fp_pc_pairs.clear();
    Thread::ClearStackFrames();
}



int32_t
ThreadMacOSX::Suspend()
{
    Log *log = ProcessMacOSXLog::GetLogIfAllCategoriesSet(PD_LOG_THREAD);
    if (log && log->GetMask().IsSet(PD_LOG_VERBOSE))
        log->Printf ("ThreadMacOSX::%s ( )", __FUNCTION__);
    lldb::tid_t tid = GetID ();
    if (ThreadIDIsValid(tid))
    {
        Error err(::thread_suspend (tid), eErrorTypeMachKernel);
        if (err.Success())
            m_suspend_count++;
        if (log || err.Fail())
            err.PutToLog(log, "::thread_suspend (%4.4x)", tid);
    }
    return GetSuspendCount();
}

int32_t
ThreadMacOSX::Resume()
{
    Log *log = ProcessMacOSXLog::GetLogIfAllCategoriesSet(PD_LOG_THREAD);
    if (log && log->GetMask().IsSet(PD_LOG_VERBOSE))
        log->Printf ("ThreadMacOSX::%s ()", __FUNCTION__);
    lldb::tid_t tid = GetID ();
    if (ThreadIDIsValid(tid))
    {
        while (m_suspend_count > 0)
        {
            Error err(::thread_resume (tid), eErrorTypeMachKernel);
            if (err.Success())
                m_suspend_count--;
            if (log || err.Fail())
                err.PutToLog(log, "::thread_resume (%4.4x)", tid);
        }
    }
    return GetSuspendCount();
}

bool
ThreadMacOSX::RestoreSuspendCount()
{
    Log *log = ProcessMacOSXLog::GetLogIfAllCategoriesSet(PD_LOG_THREAD);
    if (log && log->GetMask().IsSet(PD_LOG_VERBOSE))
        log->Printf ("ThreadMacOSX::%s ( )", __FUNCTION__);
    Error err;
    lldb::tid_t tid = GetID ();
    if (ThreadIDIsValid(tid) == false)
        return false;
    else if (m_suspend_count > m_basic_info.suspend_count)
    {
        while (m_suspend_count > m_basic_info.suspend_count)
        {
            err = ::thread_resume (tid);
            if (err.Success())
                --m_suspend_count;
            if (log || err.Fail())
                err.PutToLog(log, "::thread_resume (%4.4x)", tid);
        }
    }
    else if (m_suspend_count < m_basic_info.suspend_count)
    {
        while (m_suspend_count < m_basic_info.suspend_count)
        {
            err = ::thread_suspend (tid);
            if (err.Success())
                --m_suspend_count;
            if (log || err.Fail())
                err.PutToLog(log, "::thread_suspend (%4.4x)", tid);
        }
    }
    return  m_suspend_count == m_basic_info.suspend_count;
}


const char *
ThreadMacOSX::GetBasicInfoAsString ()
{
    if (m_basic_info_string.empty())
    {
        StreamString sstr;
        struct thread_basic_info basicInfo;

        lldb::tid_t tid = GetID ();
        if (GetBasicInfo(tid, &basicInfo))
        {
//          char run_state_str[32];
//          size_t run_state_str_size = sizeof(run_state_str);
//          switch (basicInfo.run_state)
//          {
//          case TH_STATE_RUNNING:          strncpy(run_state_str, "running", run_state_str_size); break;
//          case TH_STATE_STOPPED:          strncpy(run_state_str, "stopped", run_state_str_size); break;
//          case TH_STATE_WAITING:          strncpy(run_state_str, "waiting", run_state_str_size); break;
//          case TH_STATE_UNINTERRUPTIBLE:  strncpy(run_state_str, "uninterruptible", run_state_str_size); break;
//          case TH_STATE_HALTED:           strncpy(run_state_str, "halted", run_state_str_size); break;
//          default:                        snprintf(run_state_str, run_state_str_size, "%d", basicInfo.run_state); break;    // ???
//          }
            float user = (float)basicInfo.user_time.seconds + (float)basicInfo.user_time.microseconds / 1000000.0f;
            float system = (float)basicInfo.user_time.seconds + (float)basicInfo.user_time.microseconds / 1000000.0f;
            sstr.Printf("Thread 0x%4.4x: user=%f system=%f cpu=%d sleep_time=%d",
                InferiorThreadID(),
                user,
                system,
                basicInfo.cpu_usage,
                basicInfo.sleep_time);
            m_basic_info_string.assign (sstr.GetData(), sstr.GetSize());
        }
    }
    if (m_basic_info_string.empty())
        return NULL;
    return m_basic_info_string.c_str();
}


//const uint8_t *
//ThreadMacOSX::SoftwareBreakpointOpcode (size_t break_op_size) const
//{
//  return m_context->SoftwareBreakpointOpcode(break_op_size);
//}


lldb::tid_t
ThreadMacOSX::InferiorThreadID() const
{
    mach_msg_type_number_t i;
    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t ncount, tcount;
    lldb::tid_t inferior_tid = LLDB_INVALID_THREAD_ID;
    task_t my_task = ::mach_task_self();
    task_t task = GetMacOSXProcess().Task().GetTaskPort();

    kern_return_t kret = ::mach_port_names (task, &names, &ncount, &types, &tcount);
    if (kret == KERN_SUCCESS)
    {
        lldb::tid_t tid = GetID ();

        for (i = 0; i < ncount; i++)
        {
            mach_port_t my_name;
            mach_msg_type_name_t my_type;

            kret = ::mach_port_extract_right (task, names[i], MACH_MSG_TYPE_COPY_SEND, &my_name, &my_type);
            if (kret == KERN_SUCCESS)
            {
                ::mach_port_deallocate (my_task, my_name);
                if (my_name == tid)
                {
                    inferior_tid = names[i];
                    break;
                }
            }
        }
        // Free up the names and types
        ::vm_deallocate (my_task, (vm_address_t) names, ncount * sizeof (mach_port_name_t));
        ::vm_deallocate (my_task, (vm_address_t) types, tcount * sizeof (mach_port_type_t));
    }
    return inferior_tid;
}

bool
ThreadMacOSX::GetBasicInfo(lldb::tid_t thread, struct thread_basic_info *basicInfoPtr)
{
    if (ThreadIDIsValid(thread))
    {
        unsigned int info_count = THREAD_BASIC_INFO_COUNT;
        kern_return_t err = ::thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) basicInfoPtr, &info_count);
        if (err == KERN_SUCCESS)
            return true;
    }
    ::memset (basicInfoPtr, 0, sizeof (struct thread_basic_info));
    return false;
}


bool
ThreadMacOSX::ThreadIDIsValid (lldb::tid_t thread)
{
    return thread != 0;
}

void
ThreadMacOSX::Dump(Log *log, uint32_t index)
{
    const char * thread_run_state = NULL;

    switch (m_basic_info.run_state)
    {
    case TH_STATE_RUNNING:          thread_run_state = "running"; break;    // 1 thread is running normally
    case TH_STATE_STOPPED:          thread_run_state = "stopped"; break;    // 2 thread is stopped
    case TH_STATE_WAITING:          thread_run_state = "waiting"; break;    // 3 thread is waiting normally
    case TH_STATE_UNINTERRUPTIBLE:  thread_run_state = "uninter"; break;    // 4 thread is in an uninterruptible wait
    case TH_STATE_HALTED:           thread_run_state = "halted "; break;     // 5 thread is halted at a
    default:                        thread_run_state = "???"; break;
    }

    RegisterContext *reg_context = GetRegisterContext();
    log->Printf ("thread[%u] %4.4x (%u): pc: 0x%8.8llx sp: 0x%8.8llx breakID: %d  user: %d.%06.6d  system: %d.%06.6d  cpu: %d  policy: %d  run_state: %d (%s)  flags: %d suspend_count: %d (current %d) sleep_time: %d",
        index,
        GetID (),
        reg_context->GetPC (LLDB_INVALID_ADDRESS),
        reg_context->GetSP (LLDB_INVALID_ADDRESS),
        m_basic_info.user_time.seconds,        m_basic_info.user_time.microseconds,
        m_basic_info.system_time.seconds,    m_basic_info.system_time.microseconds,
        m_basic_info.cpu_usage,
        m_basic_info.policy,
        m_basic_info.run_state,
        thread_run_state,
        m_basic_info.flags,
        m_basic_info.suspend_count, m_suspend_count,
        m_basic_info.sleep_time);
    //DumpRegisterState(0);
}

void
ThreadMacOSX::ThreadWillResume (StateType resume_state)
{
    // Update the thread state to be the state we wanted when the task resumes
    SetState (resume_state);
    switch (resume_state)
    {
    case eStateSuspended:
        Suspend();
        break;

    case eStateRunning:
    case eStateStepping:
        Resume();
        break;
    }
    m_context->ThreadWillResume();
}

void
ThreadMacOSX::DidResume ()
{
    // TODO: cache current stack frames for next time in case we can match things up??
    ClearStackFrames();
    m_stop_exception.Clear();
    Thread::DidResume();
}

bool
ThreadMacOSX::ShouldStop(bool &step_more)
{
// TODO: REmove this after all is working, Process should be managing this
// for us.
//
//    // See if this thread is at a breakpoint?
//    lldb::user_id_t breakID = CurrentBreakpoint();
//
//    if (LLDB_BREAK_ID_IS_VALID(breakID))
//    {
//        // This thread is sitting at a breakpoint, ask the breakpoint
//        // if we should be stopping here.
//        if (Process()->Breakpoints().ShouldStop(ProcessID(), ThreadID(), breakID))
//            return true;
//        else
//        {
//            // The breakpoint said we shouldn't stop, but we may have gotten
//            // a signal or the user may have requested to stop in some other
//            // way. Stop if we have a valid exception (this thread won't if
//            // another thread was the reason this process stopped) and that
//            // exception, is NOT a breakpoint exception (a common case would
//            // be a SIGINT signal).
//            if (GetStopException().IsValid() && !GetStopException().IsBreakpoint())
//                return true;
//        }
//    }
//    else
//    {
        if (m_context->StepNotComplete())
        {
            step_more = true;
            return false;
        }
//        // The thread state is used to let us know what the thread was
//        // trying to do. ThreadMacOSX::ThreadWillResume() will set the
//        // thread state to various values depending if the thread was
//        // the current thread and if it was to be single stepped, or
//        // resumed.
//        if (GetState() == eStateRunning)
//        {
//            // If our state is running, then we should continue as we are in
//            // the process of stepping over a breakpoint.
//            return false;
//        }
//        else
//        {
//            // Stop if we have any kind of valid exception for this
//            // thread.
//            if (GetStopException().IsValid())
//                return true;
//        }
//    }
//    return false;
    return true;
}

bool
ThreadMacOSX::NotifyException(MachException::Data& exc)
{
    if (m_stop_exception.IsValid())
    {
        // We may have more than one exception for a thread, but we need to
        // only remember the one that we will say is the reason we stopped.
        // We may have been single stepping and also gotten a signal exception,
        // so just remember the most pertinent one.
        if (m_stop_exception.IsBreakpoint())
            m_stop_exception = exc;
    }
    else
    {
        m_stop_exception = exc;
    }
//    bool handled =
    m_context->NotifyException(exc);
//    if (!handled)
//    {
//        handled = true;
//        lldb::addr_t pc = GetPC();
//        lldb::user_id_t breakID = m_process.Breakpoints().FindIDCyAddress(pc);
//        SetCurrentBreakpoint(breakID);
//        switch (exc.exc_type)
//        {
//        case EXC_BAD_ACCESS:
//            break;
//        case EXC_BAD_INSTRUCTION:
//            break;
//        case EXC_ARITHMETIC:
//            break;
//        case EXC_EMULATION:
//            break;
//        case EXC_SOFTWARE:
//            break;
//        case EXC_BREAKPOINT:
//            break;
//        case EXC_SYSCALL:
//            break;
//        case EXC_MACH_SYSCALL:
//            break;
//        case EXC_RPC_ALERT:
//            break;
//        }
//    }
//    return handled;
    return true;
}

RegisterContext *
ThreadMacOSX::GetRegisterContext ()
{
    if (m_reg_context_sp.get() == NULL)
        m_reg_context_sp.reset (CreateRegisterContextForFrame (NULL));
    return m_reg_context_sp.get();
}

RegisterContext *
ThreadMacOSX::CreateRegisterContextForFrame (StackFrame *frame)
{
    return m_context->CreateRegisterContext (frame);
}

uint32_t
ThreadMacOSX::SetHardwareBreakpoint (const BreakpointSite *bp)
{
    if (bp != NULL)
        return GetRegisterContext()->SetHardwareBreakpoint(bp->GetLoadAddress(), bp->GetByteSize());
    return LLDB_INVALID_INDEX32;
}

uint32_t
ThreadMacOSX::SetHardwareWatchpoint (const WatchpointLocation *wp)
{
    if (wp != NULL)
        return GetRegisterContext()->SetHardwareWatchpoint(wp->GetLoadAddress(), wp->GetByteSize(), wp->WatchpointRead(), wp->WatchpointWrite());
    return LLDB_INVALID_INDEX32;
}


bool
ThreadMacOSX::SaveFrameZeroState (RegisterCheckpoint &checkpoint)
{
    lldb::StackFrameSP frame_sp(GetStackFrameAtIndex (0));
    if (frame_sp)
    {
        checkpoint.SetStackID(frame_sp->GetStackID());
        return frame_sp->GetRegisterContext()->ReadAllRegisterValues (checkpoint.GetData());
    }
    return false;
}

bool
ThreadMacOSX::RestoreSaveFrameZero (const RegisterCheckpoint &checkpoint)
{
    lldb::StackFrameSP frame_sp(GetStackFrameAtIndex (0));
    if (frame_sp)
    {
        bool ret = frame_sp->GetRegisterContext()->WriteAllRegisterValues (checkpoint.GetData());

        // Clear out all stack frames as our world just changed.
        ClearStackFrames();
        frame_sp->GetRegisterContext()->Invalidate();

        return ret;
    }
    return false;
}

bool
ThreadMacOSX::ClearHardwareBreakpoint (const BreakpointSite *bp)
{
    if (bp != NULL && bp->IsHardware())
        return GetRegisterContext()->ClearHardwareBreakpoint(bp->GetHardwareIndex());
    return false;
}

bool
ThreadMacOSX::ClearHardwareWatchpoint (const WatchpointLocation *wp)
{
    if (wp != NULL && wp->IsHardware())
        return GetRegisterContext()->ClearHardwareWatchpoint(wp->GetHardwareIndex());
    return false;
}

size_t
ThreadMacOSX::GetStackFrameData(std::vector<std::pair<lldb::addr_t, lldb::addr_t> >& fp_pc_pairs)
{
    lldb::StackFrameSP frame_sp(GetStackFrameAtIndex (0));
    return m_context->GetStackFrameData(frame_sp.get(), fp_pc_pairs);
}


//void
//ThreadMacOSX::NotifyBreakpointChanged (const BreakpointSite *bp)
//{
//  if (bp)
//  {
//      lldb::user_id_t breakID = bp->GetID();
//      if (bp->IsEnabled())
//      {
//          if (bp->Address() == GetPC())
//          {
//              SetCurrentBreakpoint(breakID);
//          }
//      }
//      else
//      {
//          if (CurrentBreakpoint() == breakID)
//          {
//              SetCurrentBreakpoint(LLDB_INVALID_BREAK_ID);
//          }
//      }
//  }
//}
//


