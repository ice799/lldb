//===-- DisassemblerLLVM.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "DisassemblerLLVM.h"

#include "llvm-c/EnhancedDisassembly.h"

#include "lldb/Core/Address.h"
#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/Disassembler.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Stream.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Symbol/SymbolContext.h"

#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"

#include <memory>
#include <string>

using namespace lldb;
using namespace lldb_private;


static
int DataExtractorByteReader(uint8_t *byte, uint64_t address, void *arg)
{
    DataExtractor &extractor = *((DataExtractor *)arg);

    if (extractor.ValidOffset(address))
    {
        *byte = *(extractor.GetDataStart() + address);
        return 0;
    }
    else
    {
        return -1;
    }
}

namespace {
    struct RegisterReaderArg {
        const lldb::addr_t instructionPointer;
        const EDDisassemblerRef disassembler;

        RegisterReaderArg(lldb::addr_t ip,
                          EDDisassemblerRef dis) :
            instructionPointer(ip),
            disassembler(dis)
        {
        }
    };
}

static int IPRegisterReader(uint64_t *value, unsigned regID, void* arg)
{
    uint64_t instructionPointer = ((RegisterReaderArg*)arg)->instructionPointer;
    EDDisassemblerRef disassembler = ((RegisterReaderArg*)arg)->disassembler;

    if(EDRegisterIsProgramCounter(disassembler, regID)) {
        *value = instructionPointer;
        return 0;
    }

    return -1;
}

DisassemblerLLVM::Instruction::Instruction(EDDisassemblerRef disassembler) :
    Disassembler::Instruction (),
    m_disassembler (disassembler)
{
}

DisassemblerLLVM::Instruction::~Instruction()
{
}

static void
PadString(Stream *s, const std::string &str, size_t width)
{
    int diff = width - str.length();

    if (diff > 0)
        s->Printf("%s%*.*s", str.c_str(), diff, diff, "");
    else
        s->Printf("%s ", str.c_str());
}

void
DisassemblerLLVM::Instruction::Dump
(
    Stream *s,
    lldb_private::Address *inst_addr_ptr,
    const DataExtractor *bytes,
    uint32_t bytes_offset,
    const lldb_private::ExecutionContext& exe_ctx,
    bool raw
)
{
    const size_t opcodeColumnWidth = 7;
    const size_t operandColumnWidth = 25;

    ExecutionContextScope *exe_scope = exe_ctx.GetBestExecutionContextScope();
    // If we have an address, print it out
    if (inst_addr_ptr)
    {
        if (inst_addr_ptr->Dump (s, 
                                 exe_scope, 
                                 Address::DumpStyleLoadAddress, 
                                 Address::DumpStyleModuleWithFileAddress,
                                 0))
            s->PutCString(":  ");
    }

    // If we are supposed to show bytes, "bytes" will be non-NULL.
    if (bytes)
    {
        uint32_t bytes_dumped = bytes->Dump(s, bytes_offset, eFormatBytes, 1, EDInstByteSize(m_inst), UINT32_MAX, LLDB_INVALID_ADDRESS, 0, 0) - bytes_offset;
        // Allow for 8 bytes of opcodes normally
        const uint32_t default_num_opcode_bytes = 9;
        if (bytes_dumped * 3 < (default_num_opcode_bytes*3))
        {
            uint32_t indent_level = (default_num_opcode_bytes*3) - (bytes_dumped * 3);
            s->Printf("%*.*s", indent_level, indent_level, "");
        }
    }

    int numTokens = EDNumTokens(m_inst);

    int currentOpIndex = -1;

    lldb_private::Process *process = exe_ctx.process;
    addr_t base_addr = LLDB_INVALID_ADDRESS;
    if (process && process->IsAlive())
        base_addr = inst_addr_ptr->GetLoadAddress (process);
    if (base_addr == LLDB_INVALID_ADDRESS)
        base_addr = inst_addr_ptr->GetFileAddress ();

    RegisterReaderArg rra(base_addr + EDInstByteSize(m_inst), m_disassembler);


    bool printTokenized = false;

    if (numTokens != -1)
    {
        printTokenized = true;

        // Handle the opcode column.

        StreamString opcode;

        int tokenIndex = 0;

        EDTokenRef token;
        const char *tokenStr;

        if (EDGetToken(&token, m_inst, tokenIndex))
            printTokenized = false;

        if (!printTokenized || !EDTokenIsOpcode(token))
            printTokenized = false;

        if (!printTokenized || EDGetTokenString(&tokenStr, token))
            printTokenized = false;

        // Put the token string into our opcode string
        opcode.PutCString(tokenStr);

        // If anything follows, it probably starts with some whitespace.  Skip it.

        tokenIndex++;

        if (printTokenized && tokenIndex < numTokens)
        {
            if(!printTokenized || EDGetToken(&token, m_inst, tokenIndex))
                printTokenized = false;

            if(!printTokenized || !EDTokenIsWhitespace(token))
                printTokenized = false;
        }

        tokenIndex++;

        // Handle the operands and the comment.

        StreamString operands;
        StreamString comment;

        if (printTokenized)
        {
            bool show_token;

            for (; tokenIndex < numTokens; ++tokenIndex)
            {
                if (EDGetToken(&token, m_inst, tokenIndex))
                    return;

                if (raw)
                {
                    show_token = true;
                }
                else
                {
                    int operandIndex = EDOperandIndexForToken(token);

                    if (operandIndex >= 0)
                    {
                        if (operandIndex != currentOpIndex)
                        {
                            show_token = true;

                            currentOpIndex = operandIndex;
                            EDOperandRef operand;

                            if (!EDGetOperand(&operand, m_inst, currentOpIndex))
                            {
                                if (EDOperandIsMemory(operand))
                                {
                                    uint64_t operand_value;

                                    if (!EDEvaluateOperand(&operand_value, operand, IPRegisterReader, &rra))
                                    {
                                        if (EDInstIsBranch(m_inst))
                                        {
                                            operands.Printf("0x%llx ", operand_value);
                                            show_token = false;
                                        }
                                        else
                                        {
                                            // Put the address value into the comment
                                            comment.Printf("0x%llx ", operand_value);
                                        }

                                        lldb_private::Address so_addr;
                                        if (process && process->IsAlive())
                                        {
                                            if (process->ResolveLoadAddress (operand_value, so_addr))
                                                so_addr.Dump(&comment, exe_scope, Address::DumpStyleResolvedDescriptionNoModule, Address::DumpStyleSectionNameOffset);
                                        }
                                        else if (inst_addr_ptr)
                                        {
                                            Module *module = inst_addr_ptr->GetModule();
                                            if (module)
                                            {
                                                if (module->ResolveFileAddress (operand_value, so_addr))
                                                    so_addr.Dump(&comment, exe_scope, Address::DumpStyleResolvedDescriptionNoModule, Address::DumpStyleSectionNameOffset);
                                            }
                                        }

                                    } // EDEvaluateOperand
                                } // EDOperandIsMemory
                            } // EDGetOperand
                        } // operandIndex != currentOpIndex
                    } // operandIndex >= 0
                } // else(raw)

                if (show_token)
                {
                    if(EDGetTokenString(&tokenStr, token))
                    {
                        printTokenized = false;
                        break;
                    }

                    operands.PutCString(tokenStr);
                }
            } // for (tokenIndex)

            if (printTokenized)
            {
                if (operands.GetString().empty())
                {
                    s->PutCString(opcode.GetString().c_str());
                }
                else
                {
                    PadString(s, opcode.GetString(), opcodeColumnWidth);

                    if (comment.GetString().empty())
                    {
                        s->PutCString(operands.GetString().c_str());
                    }
                    else
                    {
                        PadString(s, operands.GetString(), operandColumnWidth);

                        s->PutCString("; ");
                        s->PutCString(comment.GetString().c_str());
                    } // else (comment.GetString().empty())
                } // else (operands.GetString().empty())
            } // printTokenized
        } // for (tokenIndex)
    } // numTokens != -1

    if (!printTokenized)
    {
        const char *str;

        if (EDGetInstString(&str, m_inst))
            return;
        else
            s->PutCString(str);
    }
}

bool
DisassemblerLLVM::Instruction::DoesBranch() const
{
    return EDInstIsBranch(m_inst);
}

size_t
DisassemblerLLVM::Instruction::GetByteSize() const
{
    return EDInstByteSize(m_inst);
}

size_t
DisassemblerLLVM::Instruction::Extract(const DataExtractor &data, uint32_t data_offset)
{
    if (EDCreateInsts(&m_inst, 1, m_disassembler, DataExtractorByteReader, data_offset, (void*)(&data)))
        return EDInstByteSize(m_inst);
    else
        return 0;
}

static inline const char *
TripleForArchSpec (const ArchSpec &arch, char *triple, size_t triple_len)
{
    const char *arch_name = arch.AsCString();

    if (arch_name)
    {
        snprintf(triple, triple_len, "%s-unknown-unknown", arch_name);
        return triple;
    }
    return NULL;
}

static inline EDAssemblySyntax_t
SyntaxForArchSpec (const ArchSpec &arch)
{
    const char *arch_name = arch.AsCString();

    if (arch_name != NULL && 
       ((strcasestr (arch_name, "i386") == arch_name) || 
        (strcasestr (arch_name, "x86_64") == arch_name)))
        return kEDAssemblySyntaxX86ATT;
    
    return (EDAssemblySyntax_t)0;   // default
}

Disassembler *
DisassemblerLLVM::CreateInstance(const ArchSpec &arch)
{
    char triple[256];

    if (TripleForArchSpec (arch, triple, sizeof(triple)))
        return new DisassemblerLLVM(arch);
    return NULL;
}

DisassemblerLLVM::DisassemblerLLVM(const ArchSpec &arch) :
    Disassembler(arch)
{
    char triple[256];
    if (TripleForArchSpec (arch, triple, sizeof(triple)))
    {
        assert(!EDGetDisassembler(&m_disassembler, triple, SyntaxForArchSpec (arch)) && "No disassembler created!");
    }
}

DisassemblerLLVM::~DisassemblerLLVM()
{
}

size_t
DisassemblerLLVM::DecodeInstructions
(
    const DataExtractor& data,
    uint32_t data_offset,
    uint32_t num_instructions
)
{
    size_t total_inst_byte_size = 0;

    m_instruction_list.Clear();

    while (data.ValidOffset(data_offset) && num_instructions)
    {
        Instruction::shared_ptr inst_sp (new Instruction(m_disassembler));

        size_t inst_byte_size = inst_sp->Extract(data, data_offset);

        if (inst_byte_size == 0)
            break;

        m_instruction_list.AppendInstruction(inst_sp);

        total_inst_byte_size += inst_byte_size;
        data_offset += inst_byte_size;
        num_instructions--;
    }

    return total_inst_byte_size;
}

void
DisassemblerLLVM::Initialize()
{
    PluginManager::RegisterPlugin (GetPluginNameStatic(),
                                   GetPluginDescriptionStatic(),
                                   CreateInstance);
}

void
DisassemblerLLVM::Terminate()
{
    PluginManager::UnregisterPlugin (CreateInstance);
}


const char *
DisassemblerLLVM::GetPluginNameStatic()
{
    return "disassembler.llvm";
}

const char *
DisassemblerLLVM::GetPluginDescriptionStatic()
{
    return "Disassembler that uses LLVM opcode tables to disassemble i386 and x86_64.";
}

//------------------------------------------------------------------
// PluginInterface protocol
//------------------------------------------------------------------
const char *
DisassemblerLLVM::GetPluginName()
{
    return "DisassemblerLLVM";
}

const char *
DisassemblerLLVM::GetShortPluginName()
{
    return GetPluginNameStatic();
}

uint32_t
DisassemblerLLVM::GetPluginVersion()
{
    return 1;
}

void
DisassemblerLLVM::GetPluginCommandHelp (const char *command, Stream *strm)
{
}

Error
DisassemblerLLVM::ExecutePluginCommand (Args &command, Stream *strm)
{
    Error error;
    error.SetErrorString("No plug-in command are currently supported.");
    return error;
}

Log *
DisassemblerLLVM::EnablePluginLogging (Stream *strm, Args &command)
{
    return NULL;
}

