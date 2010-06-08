//===-- VariableList.h ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_VariableList_h_
#define liblldb_VariableList_h_

#include "lldb/lldb-private.h"
#include "lldb/Symbol/SymbolContext.h"
#include "lldb/Symbol/Variable.h"

namespace lldb_private {

class VariableList
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
//  VariableList(const SymbolContext &symbol_context);
    VariableList();
    virtual ~VariableList();

    void
    AddVariable (lldb::VariableSP &var_sp);

    void
    AddVariables(VariableList *variable_list);

    void
    Clear();

    void
    Dump(Stream *s, bool show_context) const;

    lldb::VariableSP
    GetVariableAtIndex(uint32_t idx);

    lldb::VariableSP
    FindVariable(const ConstString& name);

//  const SymbolContext&
//  GetSymbolContext() const
//  {
//      return m_symbol_context;
//  }
//
    size_t
    MemorySize() const;

    size_t
    GetSize() const;

protected:
    typedef std::vector<lldb::VariableSP> collection;
    typedef collection::iterator iterator;
    typedef collection::const_iterator const_iterator;

    collection m_variables;
private:
    //------------------------------------------------------------------
    // For VariableList only
    //------------------------------------------------------------------
    DISALLOW_COPY_AND_ASSIGN (VariableList);
};

} // namespace lldb_private

#endif  // liblldb_VariableList_h_
