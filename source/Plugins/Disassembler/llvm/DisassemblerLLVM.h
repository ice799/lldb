//===-- DisassemblerLLVM.h --------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_DisassemblerLLVM_h_
#define liblldb_DisassemblerLLVM_h_

#include "lldb/Core/Disassembler.h"
#include "lldb/Host/Mutex.h"

struct EDDisassembler;
typedef EDDisassembler *EDDisassemblerRef;

struct EDInst;
typedef EDInst *EDInstRef;

class DisassemblerLLVM : public lldb_private::Disassembler
{
public:
    class Instruction : public lldb_private::Disassembler::Instruction
    {
    public:
        Instruction(EDDisassemblerRef disassembler);

        virtual
        ~Instruction();

        void
        Dump (lldb_private::Stream *s,
              lldb_private::Address *instr_addr_ptr,
              const lldb_private::DataExtractor *bytes,
              uint32_t bytes_offset,
              const lldb_private::ExecutionContext& exe_ctx,
              bool raw);

        bool
        DoesBranch () const;

        size_t
        GetByteSize() const;

        size_t
        Extract (const lldb_private::DataExtractor &data,
                 uint32_t data_offset);

    protected:
        EDDisassemblerRef m_disassembler;
        EDInstRef m_inst;
    };

    //------------------------------------------------------------------
    // Static Functions
    //------------------------------------------------------------------
    static void
    Initialize();

    static void
    Terminate();

    static const char *
    GetPluginNameStatic();

    static const char *
    GetPluginDescriptionStatic();

    static lldb_private::Disassembler *
    CreateInstance(const lldb_private::ArchSpec &arch);


    DisassemblerLLVM(const lldb_private::ArchSpec &arch);

    virtual
    ~DisassemblerLLVM();

    size_t
    DecodeInstructions (const lldb_private::DataExtractor& data,
                        uint32_t data_offset,
                        uint32_t num_instructions);
    
    //------------------------------------------------------------------
    // PluginInterface protocol
    //------------------------------------------------------------------
    virtual const char *
    GetPluginName();

    virtual const char *
    GetShortPluginName();

    virtual uint32_t
    GetPluginVersion();

    virtual void
    GetPluginCommandHelp (const char *command, lldb_private::Stream *strm);

    virtual lldb_private::Error
    ExecutePluginCommand (lldb_private::Args &command, lldb_private::Stream *strm);

    virtual lldb_private::Log *
    EnablePluginLogging (lldb_private::Stream *strm, lldb_private::Args &command);

protected:
    EDDisassemblerRef m_disassembler;
};

#endif  // liblldb_DisassemblerLLVM_h_
