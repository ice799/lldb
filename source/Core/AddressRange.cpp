//===-- AddressRange.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/AddressRange.h"
#include "lldb/Core/Stream.h"
#include "lldb/Target/Process.h"

using namespace lldb;
using namespace lldb_private;

AddressRange::AddressRange () :
    m_base_addr(),
    m_byte_size(0)
{
}

AddressRange::AddressRange (addr_t file_addr, addr_t byte_size, const SectionList *section_list) :
    m_base_addr(file_addr, section_list),
    m_byte_size(byte_size)
{
}

AddressRange::AddressRange (const Section* section, addr_t offset, addr_t byte_size) :
    m_base_addr(section, offset),
    m_byte_size(byte_size)
{
}

AddressRange::AddressRange (const Address& so_addr, addr_t byte_size) :
    m_base_addr(so_addr),
    m_byte_size(byte_size)
{
}

AddressRange::~AddressRange ()
{
}

//bool
//AddressRange::Contains (const Address &addr) const
//{
//    const addr_t byte_size = GetByteSize();
//    if (byte_size)
//        return addr.GetSection() == m_base_addr.GetSection() && (addr.GetOffset() - m_base_addr.GetOffset()) < byte_size;
//}
//
//bool
//AddressRange::Contains (const Address *addr) const
//{
//    if (addr)
//        return Contains (*addr);
//    return false;
//}

bool
AddressRange::ContainsFileAddress (const Address &addr) const
{
    if (addr.GetSection() == m_base_addr.GetSection())
        return (addr.GetOffset() - m_base_addr.GetOffset()) < GetByteSize();
    addr_t file_base_addr = GetBaseAddress().GetFileAddress();
    if (file_base_addr == LLDB_INVALID_ADDRESS)
        return false;

    addr_t file_addr = addr.GetFileAddress();
    if (file_addr == LLDB_INVALID_ADDRESS)
        return false;

    if (file_base_addr <= file_addr)
        return (file_addr - file_base_addr) < GetByteSize();

    return false;
}

bool
AddressRange::ContainsFileAddress (addr_t file_addr) const
{
    if (file_addr == LLDB_INVALID_ADDRESS)
        return false;

    addr_t file_base_addr = GetBaseAddress().GetFileAddress();
    if (file_base_addr == LLDB_INVALID_ADDRESS)
        return false;

    if (file_base_addr <= file_addr)
        return (file_addr - file_base_addr) < GetByteSize();

    return false;
}


bool
AddressRange::ContainsLoadAddress (const Address &addr, Process *process) const
{
    if (addr.GetSection() == m_base_addr.GetSection())
        return (addr.GetOffset() - m_base_addr.GetOffset()) < GetByteSize();
    addr_t load_base_addr = GetBaseAddress().GetLoadAddress(process);
    if (load_base_addr == LLDB_INVALID_ADDRESS)
        return false;

    addr_t load_addr = addr.GetLoadAddress(process);
    if (load_addr == LLDB_INVALID_ADDRESS)
        return false;

    if (load_base_addr <= load_addr)
        return (load_addr - load_base_addr) < GetByteSize();

    return false;
}

bool
AddressRange::ContainsLoadAddress (addr_t load_addr, Process *process) const
{
    if (load_addr == LLDB_INVALID_ADDRESS)
        return false;

    addr_t load_base_addr = GetBaseAddress().GetLoadAddress(process);
    if (load_base_addr == LLDB_INVALID_ADDRESS)
        return false;

    if (load_base_addr <= load_addr)
        return (load_addr - load_base_addr) < GetByteSize();

    return false;
}

void
AddressRange::Clear()
{
    m_base_addr.Clear();
    m_byte_size = 0;
}

bool
AddressRange::Dump(Stream *s, Process *process, Address::DumpStyle style, Address::DumpStyle fallback_style) const
{
    addr_t vmaddr = LLDB_INVALID_ADDRESS;
    int addr_size = sizeof (addr_t);
    if (process)
      addr_size = process->GetAddressByteSize ();

    switch (style)
    {
    case Address::DumpStyleSectionNameOffset:
    case Address::DumpStyleSectionPointerOffset:
        s->PutChar ('[');
        m_base_addr.Dump(s, process, style, fallback_style);
        s->PutChar ('-');
        s->Address (m_base_addr.GetOffset() + GetByteSize(), addr_size);
        s->PutChar (')');
        return true;
        break;

    case Address::DumpStyleFileAddress:
        vmaddr = m_base_addr.GetFileAddress();
        break;

    case Address::DumpStyleLoadAddress:
        vmaddr = m_base_addr.GetLoadAddress(process);
        break;
    }

    if (vmaddr != LLDB_INVALID_ADDRESS)
    {
        s->AddressRange(vmaddr, vmaddr + GetByteSize(), addr_size);
        return true;
    }

    return false;
}


void
AddressRange::DumpDebug (Stream *s) const
{
    s->Printf("%.*p: AddressRange section = %*p, offset = 0x%16.16llx, byte_size = 0x%16.16llx\n", (int)sizeof(void*) * 2, this, (int)sizeof(void*) * 2, m_base_addr.GetSection(), m_base_addr.GetOffset(), GetByteSize());
}
//
//bool
//lldb::operator==    (const AddressRange& lhs, const AddressRange& rhs)
//{
//    if (lhs.GetBaseAddress() == rhs.GetBaseAddress())
//        return lhs.GetByteSize() == rhs.GetByteSize();
//    return false;
//}
