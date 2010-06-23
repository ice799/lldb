//===-- SBCommandReturnObject.cpp -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Interpreter/CommandReturnObject.h"

#include "lldb/API/SBCommandReturnObject.h"

using namespace lldb;
using namespace lldb_private;

SBCommandReturnObject::SBCommandReturnObject () :
    m_opaque_ap (new CommandReturnObject ())
{
}

SBCommandReturnObject::~SBCommandReturnObject ()
{
    // m_opaque_ap will automatically delete any pointer it owns
}

bool
SBCommandReturnObject::IsValid() const
{
    return m_opaque_ap.get() != NULL;
}


const char *
SBCommandReturnObject::GetOutput ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->GetOutputStream().GetData();
    return NULL;
}

const char *
SBCommandReturnObject::GetError ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->GetErrorStream().GetData();
    return NULL;
}

size_t
SBCommandReturnObject::GetOutputSize ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->GetOutputStream().GetSize();
    return 0;
}

size_t
SBCommandReturnObject::GetErrorSize ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->GetErrorStream().GetSize();
    return 0;
}

size_t
SBCommandReturnObject::PutOutput (FILE *fh)
{
    if (fh)
    {
        size_t num_bytes = GetOutputSize ();
        if (num_bytes)
            return ::fprintf (fh, "%s", GetOutput());
    }
    return 0;
}

size_t
SBCommandReturnObject::PutError (FILE *fh)
{
    if (fh)
    {
        size_t num_bytes = GetErrorSize ();
        if (num_bytes)
            return ::fprintf (fh, "%s", GetError());
    }
    return 0;
}

void
SBCommandReturnObject::Clear()
{
    if (m_opaque_ap.get())
        m_opaque_ap->Clear();
}

lldb::ReturnStatus
SBCommandReturnObject::GetStatus()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->GetStatus();
    return lldb::eReturnStatusInvalid;
}

bool
SBCommandReturnObject::Succeeded ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->Succeeded();
    return false;
}

bool
SBCommandReturnObject::HasResult ()
{
    if (m_opaque_ap.get())
        return m_opaque_ap->HasResult();
    return false;
}

void
SBCommandReturnObject::AppendMessage (const char *message)
{
    if (m_opaque_ap.get())
        m_opaque_ap->AppendMessage (message);
}

CommandReturnObject *
SBCommandReturnObject::operator ->() const
{
    return m_opaque_ap.get();
}

CommandReturnObject *
SBCommandReturnObject::get() const
{
    return m_opaque_ap.get();
}

CommandReturnObject &
SBCommandReturnObject::operator *() const
{
    assert(m_opaque_ap.get());
    return *(m_opaque_ap.get());
}


CommandReturnObject &
SBCommandReturnObject::ref() const
{
    assert(m_opaque_ap.get());
    return *(m_opaque_ap.get());
}


void
SBCommandReturnObject::SetLLDBObjectPtr (CommandReturnObject *ptr)
{
    if (m_opaque_ap.get())
        m_opaque_ap.reset (ptr);
}

