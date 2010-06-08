//===-- SBAddress.cpp -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/API/SBAddress.h"
#include "lldb/API/SBProcess.h"
#include "lldb/Core/Address.h"

using namespace lldb;


SBAddress::SBAddress () :
    m_lldb_object_ap ()
{
}

SBAddress::SBAddress (const lldb_private::Address *lldb_object_ptr) :
    m_lldb_object_ap ()
{
    if (lldb_object_ptr)
        m_lldb_object_ap.reset (new lldb_private::Address(*lldb_object_ptr));
}

SBAddress::SBAddress (const SBAddress &rhs) :
    m_lldb_object_ap ()
{
    if (rhs.IsValid())
        m_lldb_object_ap.reset (new lldb_private::Address(*rhs.m_lldb_object_ap.get()));
}

SBAddress::~SBAddress ()
{
}

const SBAddress &
SBAddress::operator = (const SBAddress &rhs)
{
    if (this != &rhs)
    {
        if (rhs.IsValid())
            m_lldb_object_ap.reset (new lldb_private::Address(*rhs.m_lldb_object_ap.get()));
    }
    return *this;
}

bool
SBAddress::IsValid () const
{
    return m_lldb_object_ap.get() != NULL && m_lldb_object_ap->IsValid();
}

void
SBAddress::SetAddress (const lldb_private::Address *lldb_object_ptr)
{
    if (lldb_object_ptr)
    {
        if (m_lldb_object_ap.get())
            *m_lldb_object_ap = *lldb_object_ptr;
        else
            m_lldb_object_ap.reset (new lldb_private::Address(*lldb_object_ptr));
        return;
    }
    if (m_lldb_object_ap.get())
        m_lldb_object_ap->Clear();
}

lldb::addr_t
SBAddress::GetFileAddress () const
{
    if (m_lldb_object_ap.get())
        return m_lldb_object_ap->GetFileAddress();
    else
        return LLDB_INVALID_ADDRESS;
}

lldb::addr_t
SBAddress::GetLoadAddress (const SBProcess &process) const
{
    if (m_lldb_object_ap.get())
        return m_lldb_object_ap->GetLoadAddress(process.get());
    else
        return LLDB_INVALID_ADDRESS;
}

bool
SBAddress::OffsetAddress (addr_t offset)
{
    if (m_lldb_object_ap.get())
    {
        addr_t addr_offset = m_lldb_object_ap->GetOffset();
        if (addr_offset != LLDB_INVALID_ADDRESS)
        {
            m_lldb_object_ap->SetOffset(addr_offset + offset);
            return true;
        }
    }
    return false;
}


const lldb_private::Address *
SBAddress::operator->() const
{
    return m_lldb_object_ap.get();
}

const lldb_private::Address &
SBAddress::operator*() const
{
    return *m_lldb_object_ap;
}


