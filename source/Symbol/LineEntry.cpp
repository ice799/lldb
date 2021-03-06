//===-- LineEntry.cpp -------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Symbol/LineEntry.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Target/Process.h"

using namespace lldb_private;

LineEntry::LineEntry() :
    range(),
    file(),
    line(0),
    column(0),
    is_start_of_statement(0),
    is_start_of_basic_block(0),
    is_prologue_end(0),
    is_epilogue_begin(0),
    is_terminal_entry(0)
{
}

LineEntry::LineEntry
(
    lldb_private::Section *section,
    lldb::addr_t section_offset,
    lldb::addr_t byte_size,
    const FileSpec &_file,
    uint32_t _line,
    uint16_t _column,
    bool _is_start_of_statement,
    bool _is_start_of_basic_block,
    bool _is_prologue_end,
    bool _is_epilogue_begin,
    bool _is_terminal_entry
) :
    range(section, section_offset, byte_size),
    file(_file),
    line(_line),
    column(_column),
    is_start_of_statement(_is_start_of_statement),
    is_start_of_basic_block(_is_start_of_basic_block),
    is_prologue_end(_is_prologue_end),
    is_epilogue_begin(_is_epilogue_begin),
    is_terminal_entry(_is_terminal_entry)
{
}

void
LineEntry::Clear()
{
    range.Clear();
    file.Clear();
    line = 0;
    column = 0;
    is_start_of_statement = 0;
    is_start_of_basic_block = 0;
    is_prologue_end = 0;
    is_epilogue_begin = 0;
    is_terminal_entry = 0;
}


bool
LineEntry::IsValid() const
{
    return range.GetBaseAddress().IsValid() && line != 0;
}

bool
LineEntry::DumpStopContext(Stream *s) const
{
    bool result = false;
    if (file)
    {
        file.Dump (s);
        if (line)
            s->PutChar(':');
        result = true;
    }
    if (line)
        s->Printf ("%u", line);
    else
        result = false;

    return result;
}

bool
LineEntry::Dump
(
    Stream *s,
    Process *process,
    bool show_file,
    Address::DumpStyle style,
    Address::DumpStyle fallback_style,
    bool show_range
) const
{
    if (show_range)
    {
        // Show address range
        if (!range.Dump(s, process, style, fallback_style))
            return false;
    }
    else
    {
        // Show address only
        if (!range.GetBaseAddress().Dump(s,
                                         process,
                                         style,
                                         fallback_style))
            return false;
    }
    if (show_file)
        *s << ", file = " << file;
    if (line)
        s->Printf(", line = %u", line);
    if (column)
        s->Printf(", column = %u", column);
    if (is_start_of_statement)
        *s << ", is_start_of_statement = TRUE";

    if (is_start_of_basic_block)
        *s << ", is_start_of_basic_block = TRUE";

    if (is_prologue_end)
        *s << ", is_prologue_end = TRUE";

    if (is_epilogue_begin)
        *s << ", is_epilogue_begin = TRUE";

    if (is_terminal_entry)
        *s << ", is_terminal_entry = TRUE";
    return true;
}

bool
LineEntry::GetDescription (Stream *s, lldb::DescriptionLevel level, CompileUnit* cu, Process *process, bool show_address_only) const
{

    if (level == lldb::eDescriptionLevelBrief || level == lldb::eDescriptionLevelFull)
    {
        // Show address only
        if (show_address_only)
        {
            s->PutCString ("address = ");
            range.GetBaseAddress().Dump(s, process, Address::DumpStyleLoadAddress, Address::DumpStyleFileAddress);
        }
        else
        {
            s->PutCString ("range = ");
            range.Dump(s, process, Address::DumpStyleLoadAddress, Address::DumpStyleFileAddress);
        }

        if (file)
            *s << ' ' << file;

        if (line)
        {
            s->Printf(":%u", line);
            if (column)
                s->Printf(":%u", column);
        }

        if (level == lldb::eDescriptionLevelFull)
        {
            if (is_start_of_statement)
                *s << ", is_start_of_statement = TRUE";

            if (is_start_of_basic_block)
                *s << ", is_start_of_basic_block = TRUE";

            if (is_prologue_end)
                *s << ", is_prologue_end = TRUE";

            if (is_epilogue_begin)
                *s << ", is_epilogue_begin = TRUE";

            if (is_terminal_entry)
                *s << ", is_terminal_entry = TRUE";
        }
        else
        {
            if (is_terminal_entry)
                s->EOL();
        }
    }
    else
    {
        return Dump (s, process, true, Address::DumpStyleLoadAddress, Address::DumpStyleModuleWithFileAddress, true);
    }
    return true;
}


bool
lldb_private::operator< (const LineEntry& a, const LineEntry& b)
{
    return LineEntry::Compare (a, b) < 0;
}

int
LineEntry::Compare (const LineEntry& a, const LineEntry& b)
{
    int result = Address::CompareFileAddress (a.range.GetBaseAddress(), b.range.GetBaseAddress());
    if (result != 0)
        return result;

    const lldb::addr_t a_byte_size = a.range.GetByteSize();
    const lldb::addr_t b_byte_size = b.range.GetByteSize();

    if (a_byte_size < b_byte_size)
        return -1;
    if (a_byte_size > b_byte_size)
        return +1;

    // Check for an end sequence entry mismatch after we have determined
    // that the address values are equal. If one of the items is an end
    // sequence, we don't care about the line, file, or column info.
    if (a.is_terminal_entry > b.is_terminal_entry)
        return -1;
    if (a.is_terminal_entry < b.is_terminal_entry)
        return +1;

    if (a.line < b.line)
        return -1;
    if (a.line > b.line)
        return +1;

    if (a.column < b.column)
        return -1;
    if (a.column > b.column)
        return +1;

    return FileSpec::Compare (a.file, b.file, true);
}

