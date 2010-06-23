//===-- SBValueList.cpp -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#include "lldb/API/SBValueList.h"
#include "lldb/API/SBValue.h"

#include "lldb/Core/ValueObjectList.h"

using namespace lldb;
using namespace lldb_private;

SBValueList::SBValueList () :
    m_opaque_ap ()
{
}

SBValueList::SBValueList (const SBValueList &rhs) :
    m_opaque_ap ()
{
    if (rhs.IsValid())
        m_opaque_ap.reset (new lldb_private::ValueObjectList (*rhs));
}

SBValueList::SBValueList (const lldb_private::ValueObjectList *lldb_object_ptr) :
    m_opaque_ap ()
{
    if (lldb_object_ptr)
        m_opaque_ap.reset (new lldb_private::ValueObjectList (*lldb_object_ptr));
}

SBValueList::~SBValueList ()
{
}

bool
SBValueList::IsValid () const
{
    return (m_opaque_ap.get() != NULL);
}

const SBValueList &
SBValueList::operator = (const SBValueList &rhs)
{
    if (this != &rhs)
    {
        if (rhs.IsValid())
            m_opaque_ap.reset (new lldb_private::ValueObjectList (*rhs));
        else
            m_opaque_ap.reset ();
    }
    return *this;
}

lldb_private::ValueObjectList *
SBValueList::operator->()
{
    return m_opaque_ap.get();
}

lldb_private::ValueObjectList &
SBValueList::operator*()
{
    return *m_opaque_ap;
}

const lldb_private::ValueObjectList *
SBValueList::operator->() const
{
    return m_opaque_ap.get();
}

const lldb_private::ValueObjectList &
SBValueList::operator*() const
{
    return *m_opaque_ap;
}

void
SBValueList::Append (const SBValue &val_obj)
{
    if (val_obj.get())
    {
        CreateIfNeeded ();
        m_opaque_ap->Append (*val_obj);
    }
}

void
SBValueList::Append (lldb::ValueObjectSP& val_obj_sp)
{
    if (val_obj_sp)
    {
        CreateIfNeeded ();
        m_opaque_ap->Append (val_obj_sp);
    }
}


SBValue
SBValueList::GetValueAtIndex (uint32_t idx) const
{
    SBValue sb_value;
    if (m_opaque_ap.get())
        *sb_value = m_opaque_ap->GetValueObjectAtIndex (idx);
    return sb_value;
}

uint32_t
SBValueList::GetSize () const
{
    uint32_t size = 0;
    if (m_opaque_ap.get())
        size = m_opaque_ap->GetSize();
    return size;
}

void
SBValueList::CreateIfNeeded ()
{
    if (m_opaque_ap.get() == NULL)
        m_opaque_ap.reset (new ValueObjectList());
}


SBValue
SBValueList::FindValueObjectByUID (lldb::user_id_t uid)
{
    SBValue sb_value;
    if ( m_opaque_ap.get())
        *sb_value = m_opaque_ap->FindValueObjectByUID (uid);
    return sb_value;
}

