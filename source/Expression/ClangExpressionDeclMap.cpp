//===-- ClangExpressionDeclMap.cpp -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Expression/ClangExpressionDeclMap.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private.h"
#include "lldb/Core/Address.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/Module.h"
#include "lldb/Expression/ClangASTSource.h"
#include "lldb/Symbol/ClangASTContext.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/Function.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolContext.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Symbol/TypeList.h"
#include "lldb/Symbol/Variable.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/ExecutionContext.h"

#define DEBUG_PRINTF(...)           \
    if (log)                        \
        log->Printf(__VA_ARGS__)

using namespace lldb_private;
using namespace clang;

ClangExpressionDeclMap::ClangExpressionDeclMap(ExecutionContext *exe_ctx) :
    m_exe_ctx(exe_ctx),
    m_struct_laid_out(false)
{
    if (exe_ctx && exe_ctx->frame)
        m_sym_ctx = new SymbolContext(exe_ctx->frame->GetSymbolContext(lldb::eSymbolContextEverything));
    else
        m_sym_ctx = NULL;
}

ClangExpressionDeclMap::~ClangExpressionDeclMap()
{
    uint32_t num_tuples = m_tuples.size ();
    uint32_t tuple_index;
    
    for (tuple_index = 0; tuple_index < num_tuples; ++tuple_index)
        delete m_tuples[tuple_index].m_value;
    
    if (m_sym_ctx)
        delete m_sym_ctx;
}

bool 
ClangExpressionDeclMap::GetIndexForDecl (uint32_t &index,
                                         const clang::Decl *decl)
{
    uint32_t num_tuples = m_tuples.size ();
    uint32_t tuple_index;
    
    for (tuple_index = 0; tuple_index < num_tuples; ++tuple_index)
    {
        if (m_tuples[tuple_index].m_decl == decl) 
        {
            index = tuple_index;
            return true;
        }
    }
    
    return false;
}

// Interface for IRForTarget

bool 
ClangExpressionDeclMap::AddValueToStruct (llvm::Value *value,
                                          const clang::NamedDecl *decl,
                                          size_t size,
                                          off_t alignment)
{
    m_struct_laid_out = false;
    
    StructMemberIterator iter;
    
    for (iter = m_members.begin();
         iter != m_members.end();
         ++iter)
    {
        if (iter->m_decl == decl)
            return true;
    }

    StructMember member;
    
    member.m_value      = value;
    member.m_decl       = decl;
    member.m_offset     = 0;
    member.m_size       = size;
    member.m_alignment  = alignment;
    
    m_members.push_back(member);
    
    return true;
}

bool
ClangExpressionDeclMap::DoStructLayout ()
{
    if (m_struct_laid_out)
        return true;
    
    StructMemberIterator iter;
    
    off_t cursor = 0;
    
    m_struct_alignment = 0;
    m_struct_size = 0;
    
    for (iter = m_members.begin();
         iter != m_members.end();
         ++iter)
    {
        if (iter == m_members.begin())
            m_struct_alignment = iter->m_alignment;
        
        if (cursor % iter->m_alignment)
            cursor += (iter->m_alignment - (cursor % iter->m_alignment));
        
        iter->m_offset = cursor;
        cursor += iter->m_size;
    }
    
    m_struct_size = cursor;
    
    m_struct_laid_out = true;
    return true;
}

bool ClangExpressionDeclMap::GetStructInfo (uint32_t &num_elements,
                                            size_t &size,
                                            off_t &alignment)
{
    if (!m_struct_laid_out)
        return false;
    
    num_elements = m_members.size();
    size = m_struct_size;
    alignment = m_struct_alignment;
    
    return true;
}

bool 
ClangExpressionDeclMap::GetStructElement (const clang::NamedDecl *&decl,
                                          llvm::Value *&value,
                                          off_t &offset,
                                          uint32_t index)
{
    if (!m_struct_laid_out)
        return false;
    
    if (index >= m_members.size())
        return false;
    
    decl = m_members[index].m_decl;
    value = m_members[index].m_value;
    offset = m_members[index].m_offset;
    
    return true;
}

// Interface for DwarfExpression
Value 
*ClangExpressionDeclMap::GetValueForIndex (uint32_t index)
{
    if (index >= m_tuples.size ())
        return NULL;
    
    return m_tuples[index].m_value;
}

// Interface for ClangASTSource
void 
ClangExpressionDeclMap::GetDecls(NameSearchContext &context,
                                 const char *name)
{
    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_EXPRESSIONS);
    
    DEBUG_PRINTF("Hunting for a definition for %s", name);
    
    // Back out in all cases where we're not fully initialized
    if (!m_exe_ctx || !m_exe_ctx->frame || !m_sym_ctx)
        return;
    
    Function *function = m_sym_ctx->function;
    Block *block = m_sym_ctx->block;
    
    if (!function || !block)
    {
        DEBUG_PRINTF("function = %p, block = %p", function, block);
        return;
    }
    
    BlockList& blocks = function->GetBlocks(true);
    
    lldb::user_id_t current_block_id = block->GetID();
    
    ConstString name_cs(name);
    
    Function *fn = m_sym_ctx->FindFunctionByName(name_cs.GetCString());
    
    if (fn)
    {
        AddOneFunction(context, fn);
    }
    
    for (current_block_id = block->GetID();
         current_block_id != Block::InvalidID;
         current_block_id = blocks.GetParent(current_block_id))
    {
        Block *current_block = blocks.GetBlockByID(current_block_id);
        
        lldb::VariableListSP var_list = current_block->GetVariableList(false, true);
        
        if (!var_list)
            continue;
        
        lldb::VariableSP var = var_list->FindVariable(name_cs);
        
        if (!var)
            continue;
        
        AddOneVariable(context, var.get());
        return;
    }
    
    {
        CompileUnit *compile_unit = m_sym_ctx->comp_unit;
        
        if (!compile_unit)
        {
            DEBUG_PRINTF("compile_unit = %p", compile_unit);
            return;
        }
        
        lldb::VariableListSP var_list = compile_unit->GetVariableList(true);
        
        if (!var_list)
            return;
        
        lldb::VariableSP var = var_list->FindVariable(name_cs);
        
        if (!var)
            return;
        
        AddOneVariable(context, var.get());
        return;
    }
}

void
ClangExpressionDeclMap::AddOneVariable(NameSearchContext &context,
                                       Variable* var)
{
    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_EXPRESSIONS);
    
    Type *var_type = var->GetType();
    
    if (!var_type) 
    {
        DEBUG_PRINTF("Skipped a definition because it has no type");
        return;
    }
    
    void *var_opaque_type = var_type->GetOpaqueClangQualType();
    
    if (!var_opaque_type)
    {
        DEBUG_PRINTF("Skipped a definition because it has no Clang type");
        return;
    }
    
    DWARFExpression &var_location_expr = var->LocationExpression();
    
    TypeList *type_list = var_type->GetTypeList();
    
    if (!type_list)
    {
        DEBUG_PRINTF("Skipped a definition because the type has no associated type list");
        return;
    }
    
    clang::ASTContext *exe_ast_ctx = type_list->GetClangASTContext().getASTContext();
    
    if (!exe_ast_ctx)
    {
        DEBUG_PRINTF("There is no AST context for the current execution context");
        return;
    }
    
    std::auto_ptr<Value> var_location(new Value);
    
    Error err;
    
    if (!var_location_expr.Evaluate(m_exe_ctx, exe_ast_ctx, NULL, *var_location.get(), &err))
    {
        DEBUG_PRINTF("Error evaluating location: %s", err.AsCString());
        return;
    }
    
    void *copied_type = ClangASTContext::CopyType(context.GetASTContext(), type_list->GetClangASTContext().getASTContext(), var_opaque_type);
    
    if (var_location.get()->GetContextType() == Value::eContextTypeInvalid)
        var_location.get()->SetContext(Value::eContextTypeOpaqueClangQualType, copied_type);
    
    if (var_location.get()->GetValueType() == Value::eValueTypeFileAddress)
    {
        SymbolContext var_sc;
        var->CalculateSymbolContext(&var_sc);
    
        if (!var_sc.module_sp)
            return;
        
        ObjectFile *object_file = var_sc.module_sp->GetObjectFile();
        
        if (!object_file)
            return;
    
        Address so_addr(var_location->GetScalar().ULongLong(), object_file->GetSectionList());
        
        lldb::addr_t load_addr = so_addr.GetLoadAddress(m_exe_ctx->process);
        
        var_location->GetScalar() = load_addr;
        var_location->SetValueType(Value::eValueTypeLoadAddress);
    }
    
    NamedDecl *var_decl = context.AddVarDecl(copied_type);
    
    Tuple tuple;
    
    tuple.m_decl  = var_decl;
    tuple.m_value = var_location.release();
    
    m_tuples.push_back(tuple);
    
    DEBUG_PRINTF("Found variable");    
}

void
ClangExpressionDeclMap::AddOneFunction(NameSearchContext &context,
                                       Function* fun)
{
    Log *log = lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_EXPRESSIONS);

    Type *fun_type = fun->GetType();
    
    if (!fun_type) 
    {
        DEBUG_PRINTF("Skipped a function because it has no type");
        return;
    }
    
    void *fun_opaque_type = fun_type->GetOpaqueClangQualType();
    
    if (!fun_opaque_type)
    {
        DEBUG_PRINTF("Skipped a function because it has no Clang type");
        return;
    }
    
    std::auto_ptr<Value> fun_location(new Value);
    
    const Address &fun_address = fun->GetAddressRange().GetBaseAddress();
    lldb::addr_t load_addr = fun_address.GetLoadAddress(m_exe_ctx->process);
    fun_location->SetValueType(Value::eValueTypeLoadAddress);
    fun_location->GetScalar() = load_addr;
    
    TypeList *type_list = fun_type->GetTypeList();
    void *copied_type = ClangASTContext::CopyType(context.GetASTContext(), type_list->GetClangASTContext().getASTContext(), fun_opaque_type);
    
    NamedDecl *fun_decl = context.AddFunDecl(copied_type);
    
    Tuple tuple;
    
    tuple.m_decl  = fun_decl;
    tuple.m_value = fun_location.release();
    
    m_tuples.push_back(tuple);
    
    DEBUG_PRINTF("Found function");    
}
