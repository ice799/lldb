//===-- Disassembler.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/Disassembler.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private.h"
#include "lldb/Core/Error.h"
#include "lldb/Core/DataBufferHeap.h"
#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Timer.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Target.h"

#define DEFAULT_DISASM_BYTE_SIZE 32

using namespace lldb;
using namespace lldb_private;


Disassembler*
Disassembler::FindPlugin (const ArchSpec &arch)
{
    Timer scoped_timer (__PRETTY_FUNCTION__,
                        "Disassembler::FindPlugin (arch = %s)",
                        arch.AsCString());

    std::auto_ptr<Disassembler> disassembler_ap;
    DisassemblerCreateInstance create_callback;
    for (uint32_t idx = 0; (create_callback = PluginManager::GetDisassemblerCreateCallbackAtIndex(idx)) != NULL; ++idx)
    {
        disassembler_ap.reset (create_callback(arch));

        if (disassembler_ap.get())
            return disassembler_ap.release();
    }
    return NULL;
}



size_t
Disassembler::Disassemble
(
    Debugger &debugger,
    const ArchSpec &arch,
    const ExecutionContext &exe_ctx,
    SymbolContextList &sc_list,
    uint32_t num_mixed_context_lines,
    bool show_bytes,
    Stream &strm
)
{
    size_t success_count = 0;
    const size_t count = sc_list.GetSize();
    SymbolContext sc;
    AddressRange range;
    for (size_t i=0; i<count; ++i)
    {
        if (sc_list.GetContextAtIndex(i, sc) == false)
            break;
        if (sc.GetAddressRange(eSymbolContextFunction | eSymbolContextSymbol, range))
        {
            if (Disassemble (debugger, arch, exe_ctx, range, num_mixed_context_lines, show_bytes, strm))
            {
                ++success_count;
                strm.EOL();
            }
        }
    }
    return success_count;
}

bool
Disassembler::Disassemble
(
    Debugger &debugger,
    const ArchSpec &arch,
    const ExecutionContext &exe_ctx,
    const ConstString &name,
    Module *module,
    uint32_t num_mixed_context_lines,
    bool show_bytes,
    Stream &strm
)
{
    if (exe_ctx.target == NULL && name)
        return false;

    SymbolContextList sc_list;

    if (module)
    {
        if (!module->FindFunctions (name, 
                                    eFunctionNameTypeBase | eFunctionNameTypeFull | eFunctionNameTypeMethod | eFunctionNameTypeSelector, 
                                    true,
                                    sc_list))
            return false;
    }
    else 
    {
        if (exe_ctx.target->GetImages().FindFunctions (name, 
                                                       eFunctionNameTypeBase | eFunctionNameTypeFull | eFunctionNameTypeMethod | eFunctionNameTypeSelector, 
                                                       sc_list))
        {
            return Disassemble (debugger, arch, exe_ctx, sc_list, num_mixed_context_lines, show_bytes, strm);
        }
        else if (exe_ctx.target->GetImages().FindSymbolsWithNameAndType(name, eSymbolTypeCode, sc_list))
        {
            return Disassemble (debugger, arch, exe_ctx, sc_list, num_mixed_context_lines, show_bytes, strm);
        }
    }
    return false;
}

bool
Disassembler::Disassemble
(
    Debugger &debugger,
    const ArchSpec &arch,
    const ExecutionContext &exe_ctx,
    const AddressRange &disasm_range,
    uint32_t num_mixed_context_lines,
    bool show_bytes,
    Stream &strm
)
{
    if (disasm_range.GetByteSize())
    {
        Disassembler *disassembler = Disassembler::FindPlugin(arch);

        if (disassembler)
        {
            AddressRange range(disasm_range);
            
            Process *process = exe_ctx.process;

            // If we weren't passed in a section offset address range,
            // try and resolve it to something
            if (range.GetBaseAddress().IsSectionOffset() == false)
            {
                if (process && process->IsAlive())
                {
                    process->ResolveLoadAddress (range.GetBaseAddress().GetOffset(), range.GetBaseAddress());
                }
                else if (exe_ctx.target)
                {
                    exe_ctx.target->GetImages().ResolveFileAddress (range.GetBaseAddress().GetOffset(), range.GetBaseAddress());
                }
            }


            DataExtractor data;
            size_t bytes_disassembled = disassembler->ParseInstructions (&exe_ctx, range, data);
            if (bytes_disassembled == 0)
            {
                return false;
            }
            else
            {
                // We got some things disassembled...
                size_t num_instructions = disassembler->GetInstructionList().GetSize();
                uint32_t offset = 0;
                SymbolContext sc;
                SymbolContext prev_sc;
                AddressRange sc_range;
                if (num_mixed_context_lines)
                    strm.IndentMore ();


                Address addr(range.GetBaseAddress());
    
                // We extract the section to make sure we don't transition out
                // of the current section when disassembling
                const Section *addr_section = addr.GetSection();
                Module *range_module = range.GetBaseAddress().GetModule();

                for (size_t i=0; i<num_instructions; ++i)
                {
                    Disassembler::Instruction *inst = disassembler->GetInstructionList().GetInstructionAtIndex (i);
                    if (inst)
                    {
                        addr_t file_addr = addr.GetFileAddress();
                        if (addr_section == NULL || addr_section->ContainsFileAddress (file_addr) == false)
                        {
                            if (range_module)
                                range_module->ResolveFileAddress (file_addr, addr);
                            else if (exe_ctx.target)
                                exe_ctx.target->GetImages().ResolveFileAddress (file_addr, addr);
                                
                            addr_section = addr.GetSection();
                        }

                        prev_sc = sc;

                        if (addr_section)
                        {
                            Module *module = addr_section->GetModule();
                            uint32_t resolved_mask = module->ResolveSymbolContextForAddress(addr, eSymbolContextEverything, sc);
                            if (resolved_mask)
                            {
                                if (prev_sc.function != sc.function || prev_sc.symbol != sc.symbol)
                                {
                                    if (prev_sc.function || prev_sc.symbol)
                                        strm.EOL();

                                    strm << sc.module_sp->GetFileSpec().GetFilename();
                                    
                                    if (sc.function)
                                        strm << '`' << sc.function->GetMangled().GetName();
                                    else if (sc.symbol)
                                        strm << '`' << sc.symbol->GetMangled().GetName();
                                    strm << ":\n";
                                }

                                if (num_mixed_context_lines && !sc_range.ContainsFileAddress (addr))
                                {
                                    sc.GetAddressRange (eSymbolContextEverything, sc_range);
                                        
                                    if (sc != prev_sc)
                                    {
                                        if (offset != 0)
                                            strm.EOL();

                                        sc.DumpStopContext(&strm, process, addr);

                                        if (sc.comp_unit && sc.line_entry.IsValid())
                                        {
                                            debugger.GetSourceManager().DisplaySourceLinesWithLineNumbers (sc.line_entry.file,
                                                                                                           sc.line_entry.line,
                                                                                                           num_mixed_context_lines,
                                                                                                           num_mixed_context_lines,
                                                                                                           num_mixed_context_lines ? "->" : "",
                                                                                                           &strm);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                sc.Clear();
                            }
                        }
                        if (num_mixed_context_lines)
                            strm.IndentMore ();
                        strm.Indent();
                        size_t inst_byte_size = inst->GetByteSize();
                        inst->Dump(&strm, &addr, show_bytes ? &data : NULL, offset, exe_ctx, show_bytes);
                        strm.EOL();
                        offset += inst_byte_size;
                        
                        addr.SetOffset (addr.GetOffset() + inst_byte_size);

                        if (num_mixed_context_lines)
                            strm.IndentLess ();
                    }
                    else
                    {
                        break;
                    }
                }
                if (num_mixed_context_lines)
                    strm.IndentLess ();

            }
        }
        return true;
    }
    return false;
}


bool
Disassembler::Disassemble
(
    Debugger &debugger,
    const ArchSpec &arch,
    const ExecutionContext &exe_ctx,
    uint32_t num_mixed_context_lines,
    bool show_bytes,
    Stream &strm
)
{
    AddressRange range;
    if (exe_ctx.frame)
    {
        SymbolContext sc(exe_ctx.frame->GetSymbolContext(eSymbolContextFunction | eSymbolContextSymbol));
        if (sc.function)
        {
            range = sc.function->GetAddressRange();
        }
        else if (sc.symbol && sc.symbol->GetAddressRangePtr())
        {
            range = *sc.symbol->GetAddressRangePtr();
        }
        else
        {
            range.GetBaseAddress() = exe_ctx.frame->GetPC();
        }

        if (range.GetBaseAddress().IsValid() && range.GetByteSize() == 0)
            range.SetByteSize (DEFAULT_DISASM_BYTE_SIZE);
    }

    return Disassemble(debugger, arch, exe_ctx, range, num_mixed_context_lines, show_bytes, strm);
}

Disassembler::Instruction::Instruction()
{
}

Disassembler::Instruction::~Instruction()
{
}


Disassembler::InstructionList::InstructionList() :
    m_instructions()
{
}

Disassembler::InstructionList::~InstructionList()
{
}

size_t
Disassembler::InstructionList::GetSize() const
{
    return m_instructions.size();
}


Disassembler::Instruction *
Disassembler::InstructionList::GetInstructionAtIndex (uint32_t idx)
{
    if (idx < m_instructions.size())
        return m_instructions[idx].get();
    return NULL;
}

const Disassembler::Instruction *
Disassembler::InstructionList::GetInstructionAtIndex (uint32_t idx) const
{
    if (idx < m_instructions.size())
        return m_instructions[idx].get();
    return NULL;
}

void
Disassembler::InstructionList::Clear()
{
  m_instructions.clear();
}

void
Disassembler::InstructionList::AppendInstruction (Instruction::shared_ptr &inst_sp)
{
    if (inst_sp)
        m_instructions.push_back(inst_sp);
}


size_t
Disassembler::ParseInstructions
(
    const ExecutionContext *exe_ctx,
    const AddressRange &range,
    DataExtractor& data
)
{
    Target *target = exe_ctx->target;

    const addr_t byte_size = range.GetByteSize();
    if (target == NULL || byte_size == 0 || !range.GetBaseAddress().IsValid())
        return 0;

    DataBufferHeap *heap_buffer = new DataBufferHeap (byte_size, '\0');
    DataBufferSP data_sp(heap_buffer);

    Error error;
    const size_t bytes_read = target->ReadMemory (range.GetBaseAddress(), heap_buffer->GetBytes(), heap_buffer->GetByteSize(), error);
    
    if (bytes_read > 0)
    {
        if (bytes_read != heap_buffer->GetByteSize())
            heap_buffer->SetByteSize (bytes_read);

        data.SetData(data_sp);
        if (exe_ctx->process)
        {
            data.SetByteOrder(exe_ctx->process->GetByteOrder());
            data.SetAddressByteSize(exe_ctx->process->GetAddressByteSize());
        }
        else
        {
            data.SetByteOrder(target->GetArchitecture().GetDefaultEndian());
            data.SetAddressByteSize(target->GetArchitecture().GetAddressByteSize());
        }
        return DecodeInstructions (data, 0, UINT32_MAX);
    }

    return 0;
}

//----------------------------------------------------------------------
// Disassembler copy constructor
//----------------------------------------------------------------------
Disassembler::Disassembler(const ArchSpec& arch) :
    m_arch (arch),
    m_instruction_list(),
    m_base_addr(LLDB_INVALID_ADDRESS)
{

}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
Disassembler::~Disassembler()
{
}

Disassembler::InstructionList &
Disassembler::GetInstructionList ()
{
    return m_instruction_list;
}

const Disassembler::InstructionList &
Disassembler::GetInstructionList () const
{
    return m_instruction_list;
}
