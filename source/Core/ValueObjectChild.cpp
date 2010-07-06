//===-- ValueObjectChild.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/ValueObjectChild.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/ValueObjectList.h"

#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolContext.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Symbol/Variable.h"

#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/Target.h"

using namespace lldb_private;

ValueObjectChild::ValueObjectChild
(
    ValueObject* parent,
    clang::ASTContext *clang_ast,
    void *clang_type,
    const ConstString &name,
    uint32_t byte_size,
    int32_t byte_offset,
    uint32_t bitfield_bit_size,
    uint32_t bitfield_bit_offset
) :
    ValueObject (),
    m_parent (parent),
    m_clang_ast (clang_ast),
    m_clang_type (clang_type),
    m_byte_size (byte_size),
    m_byte_offset (byte_offset),
    m_bitfield_bit_size (bitfield_bit_size),
    m_bitfield_bit_offset (bitfield_bit_offset)
{
    m_name = name;
}

ValueObjectChild::~ValueObjectChild()
{
}

void *
ValueObjectChild::GetOpaqueClangQualType()
{
    return m_clang_type;
}

lldb::ValueType
ValueObjectChild::GetValueType() const
{
    return m_parent->GetValueType();
}

uint32_t
ValueObjectChild::CalculateNumChildren()
{
    return ClangASTContext::GetNumChildren (m_clang_type, true);
}

clang::ASTContext *
ValueObjectChild::GetClangAST ()
{
    return m_clang_ast;
}

size_t
ValueObjectChild::GetByteSize()
{
    return m_byte_size;
}

off_t
ValueObjectChild::GetByteOffset()
{
    return m_byte_offset;
}

uint32_t
ValueObjectChild::GetBitfieldBitSize()
{
    return m_bitfield_bit_size;
}

uint32_t
ValueObjectChild::GetBitfieldBitOffset()
{
    return m_bitfield_bit_offset;
}

ConstString
ValueObjectChild::GetTypeName()
{
    if (m_type_name.IsEmpty())
    {
        m_type_name = Type::GetClangTypeName (GetOpaqueClangQualType());
        if (m_type_name)
        {
            if (m_bitfield_bit_size > 0)
            {
                const char *clang_type_name = m_type_name.AsCString();
                if (clang_type_name)
                {
                    char bitfield_type_name[strlen(clang_type_name) + 32];
                    ::snprintf (bitfield_type_name, sizeof(bitfield_type_name), "%s:%u", clang_type_name, m_bitfield_bit_size);
                    m_type_name.SetCString(bitfield_type_name);
                }
            }
        }
    }
    return m_type_name;
}

void
ValueObjectChild::UpdateValue (ExecutionContextScope *exe_scope)
{
    m_error.Clear();
    SetValueIsValid (false);
    ValueObject* parent = m_parent;
    if (parent)
    {
        if (parent->UpdateValueIfNeeded(exe_scope))
        {
            m_value.SetContext(Value::eContextTypeOpaqueClangQualType, m_clang_type);

            // Copy the parent scalar value and the scalar value type
            m_value.GetScalar() = parent->GetValue().GetScalar();
            Value::ValueType value_type = parent->GetValue().GetValueType();
            m_value.SetValueType (value_type);

            if (ClangASTContext::IsPointerOrReferenceType (parent->GetOpaqueClangQualType()))
            {
                uint32_t offset = 0;
                m_value.GetScalar() = parent->GetDataExtractor().GetPointer(&offset);
                // For pointers, m_byte_offset should only ever be set if we
                // ValueObject::GetSyntheticArrayMemberFromPointer() was called
                if (ClangASTContext::IsPointerType (parent->GetOpaqueClangQualType()) && m_byte_offset)
                    m_value.GetScalar() += m_byte_offset;
                if (value_type == Value::eValueTypeScalar ||
                    value_type == Value::eValueTypeFileAddress)
                    m_value.SetValueType (Value::eValueTypeLoadAddress);
            }
            else
            {
                switch (value_type)
                {
                case Value::eValueTypeLoadAddress:
                case Value::eValueTypeFileAddress:
                case Value::eValueTypeHostAddress:
                    {
                        lldb::addr_t addr = m_value.GetScalar().ULongLong(LLDB_INVALID_ADDRESS);
                        if (addr == LLDB_INVALID_ADDRESS || addr == 0)
                        {
                            m_error.SetErrorStringWithFormat("Parent address is invalid: 0x%llx.\n", addr);
                            break;
                        }
                        // Set this object's scalar value to the address of its
                        // value be adding its byte offset to the parent address
                        m_value.GetScalar() += GetByteOffset();
                    }
                    break;

                case Value::eValueTypeScalar:
                    // TODO: What if this is a register value? Do we try and
                    // extract the child value from within the parent data?
                    // Probably...
                default:
                    m_error.SetErrorString ("Parent has invalid value.");
                    break;
                }
            }

            if (m_error.Success())
            {
                ExecutionContext exe_ctx (exe_scope);
                m_error = m_value.GetValueAsData (&exe_ctx, GetClangAST (), m_data, 0);
            }
        }
        else
        {
            m_error.SetErrorStringWithFormat("Parent failed to evaluate: %s.\n", parent->GetError().AsCString());
        }
    }
    else
    {
        m_error.SetErrorString("ValueObjectChild has a NULL parent ValueObject.");
    }
}


bool
ValueObjectChild::IsInScope (StackFrame *frame)
{
    return m_parent->IsInScope (frame);
}

