//===-- ValueObjectVariable.cpp ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#include "lldb/Core/ValueObjectVariable.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Core/Module.h"
#include "lldb/Core/ValueObjectList.h"
#include "lldb/Core/Value.h"

#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolContext.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Symbol/Variable.h"

#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"


using namespace lldb_private;

ValueObjectVariable::ValueObjectVariable (lldb::VariableSP &var_sp) :
    ValueObject(),
    m_variable_sp(var_sp)
{
    // Do not attempt to construct one of these objects with no variable!
    assert (m_variable_sp.get() != NULL);
    m_name = var_sp->GetName();
}

ValueObjectVariable::~ValueObjectVariable()
{
}

void *
ValueObjectVariable::GetOpaqueClangQualType ()
{
    Type *var_type = m_variable_sp->GetType();
    if (var_type)
        return var_type->GetOpaqueClangQualType();
    return NULL;
}

ConstString
ValueObjectVariable::GetTypeName()
{
    Type * var_type = m_variable_sp->GetType();
    if (var_type)
        return var_type->GetName();
    ConstString empty_type_name;
    return empty_type_name;
}

uint32_t
ValueObjectVariable::CalculateNumChildren()
{
    Type *var_type = m_variable_sp->GetType();
    if (var_type)
        return var_type->GetNumChildren(true);
    return 0;
}

clang::ASTContext *
ValueObjectVariable::GetClangAST ()
{
    return m_variable_sp->GetType()->GetClangAST();
}

size_t
ValueObjectVariable::GetByteSize()
{
    return m_variable_sp->GetType()->GetByteSize();
}

lldb::ValueType
ValueObjectVariable::GetValueType() const
{
    if (m_variable_sp)
        return m_variable_sp->GetScope();
    return lldb::eValueTypeInvalid;
}



void
ValueObjectVariable::UpdateValue (ExecutionContextScope *exe_scope)
{
    SetValueIsValid (false);
    m_error.Clear();

    Variable *variable = m_variable_sp.get();
    DWARFExpression &expr = variable->LocationExpression();
    Value old_value(m_value);
    ExecutionContext exe_ctx (exe_scope);
    if (expr.Evaluate (&exe_ctx, GetClangAST(), NULL, m_value, &m_error))
    {
        m_value.SetContext(Value::eContextTypeDCVariable, variable);

        Value::ValueType value_type = m_value.GetValueType();

        switch (value_type)
        {
        default:
            assert(!"Unhandled expression result value kind...");
            break;

        case Value::eValueTypeScalar:
            // The variable value is in the Scalar value inside the m_value.
            // We can point our m_data right to it.
            m_error = m_value.GetValueAsData (&exe_ctx, GetClangAST(), m_data, 0);
            break;

        case Value::eValueTypeFileAddress:
        case Value::eValueTypeLoadAddress:
        case Value::eValueTypeHostAddress:
            // The DWARF expression result was an address in the inferior
            // process. If this variable is an aggregate type, we just need
            // the address as the main value as all child variable objects
            // will rely upon this location and add an offset and then read
            // their own values as needed. If this variable is a simple
            // type, we read all data for it into m_data.
            // Make sure this type has a value before we try and read it
            if (ClangASTContext::IsAggregateType (GetOpaqueClangQualType()))
            {
                // this value object represents an aggregate type whose
                // children have values, but this object does not. So we
                // say we are changed if our location has changed.
                SetValueDidChange (value_type != old_value.GetValueType() || m_value.GetScalar() != old_value.GetScalar());
            }
            else
            {
                // Copy the Value and set the context to use our Variable
                // so it can extract read its value into m_data appropriately
                Value value(m_value);
                value.SetContext(Value::eContextTypeDCVariable, variable);
                m_error = value.GetValueAsData(&exe_ctx, GetClangAST(), m_data, 0);
            }
            break;
        }

        SetValueIsValid (m_error.Success());
    }
}



bool
ValueObjectVariable::IsInScope (StackFrame *frame)
{
    return m_variable_sp->IsInScope (frame);
}

