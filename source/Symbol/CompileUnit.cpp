//===-- CompileUnit.cpp -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/LineTable.h"
#include "lldb/Core/Module.h"
#include "lldb/Symbol/SymbolVendor.h"
#include "lldb/Symbol/VariableList.h"

using namespace lldb;
using namespace lldb_private;

CompileUnit::CompileUnit (Module *module, void *user_data, const char *pathname, const lldb::user_id_t cu_sym_id, Language::Type language) :
    ModuleChild(module),
    FileSpec (pathname),
    UserID(cu_sym_id),
    Language (language),
    m_user_data (user_data),
    m_flags (0),
    m_functions (),
    m_support_files (),
    m_line_table_ap (),
    m_variables()
{
    assert(module != NULL);
}

CompileUnit::CompileUnit (Module *module, void *user_data, const FileSpec &fspec, const lldb::user_id_t cu_sym_id, Language::Type language) :
    ModuleChild(module),
    FileSpec (fspec),
    UserID(cu_sym_id),
    Language (language),
    m_user_data (user_data),
    m_flags (0),
    m_functions (),
    m_support_files (),
    m_line_table_ap (),
    m_variables()
{
    assert(module != NULL);
}

CompileUnit::~CompileUnit ()
{
}

void
CompileUnit::CalculateSymbolContext(SymbolContext* sc)
{
    sc->comp_unit = this;
    GetModule()->CalculateSymbolContext(sc);
}

void
CompileUnit::DumpSymbolContext(Stream *s)
{
    GetModule()->DumpSymbolContext(s);
    s->Printf(", CompileUnit{0x%8.8x}", GetID());
}


void
CompileUnit::GetDescription(Stream *s, lldb::DescriptionLevel level) const
{
    *s << '"' << (const FileSpec&)*this << "\", id = " << (const UserID&)*this
        << ", language = " << (const Language&)*this;
}


//----------------------------------------------------------------------
// Dump the current contents of this object. No functions that cause on
// demand parsing of functions, globals, statics are called, so this
// is a good function to call to get an idea of the current contents of
// the CompileUnit object.
//----------------------------------------------------------------------
void
CompileUnit::Dump(Stream *s, bool show_context) const
{
    s->Printf("%.*p: ", (int)sizeof(void*) * 2, this);
    s->Indent();
    *s << "CompileUnit" << (const UserID&)*this
        << ", language = " << (const Language&)*this
        << ", file='" << (const FileSpec&)*this << "'\n";

//  m_types.Dump(s);

    if (m_variables.get())
    {
        s->IndentMore();
        m_variables->Dump(s, show_context);
        s->IndentLess();
    }

    if (!m_functions.empty())
    {
        s->IndentMore();
        std::vector<FunctionSP>::const_iterator pos;
        std::vector<FunctionSP>::const_iterator end = m_functions.end();
        for (pos = m_functions.begin(); pos != end; ++pos)
        {
            (*pos)->Dump(s, show_context);
        }

        s->IndentLess();
        s->EOL();
    }
}

//----------------------------------------------------------------------
// Add a function to this compile unit
//----------------------------------------------------------------------
void
CompileUnit::AddFunction(FunctionSP& funcSP)
{
    // TODO: order these by address
    m_functions.push_back(funcSP);
}

FunctionSP
CompileUnit::GetFunctionAtIndex (size_t idx)
{
    FunctionSP funcSP;
    if (idx < m_functions.size())
        funcSP = m_functions[idx];
    return funcSP;
}

//----------------------------------------------------------------------
// Find functions using the a Mangled::Tokens token list. This
// function currently implements an interative approach designed to find
// all instances of certain functions. It isn't designed to the the
// quickest way to lookup functions as it will need to iterate through
// all functions and see if they match, though it does provide a powerful
// and context sensitive way to search for all functions with a certain
// name, all functions in a namespace, or all functions of a template
// type. See Mangled::Tokens::Parse() comments for more information.
//
// The function prototype will need to change to return a list of
// results. It was originally used to help debug the Mangled class
// and the Mangled::Tokens::MatchesQuery() function and it currently
// will print out a list of matching results for the functions that
// are currently in this compile unit.
//
// A FindFunctions method should be called prior to this that takes
// a regular function name (const char * or ConstString as a parameter)
// before resorting to this slower but more complete function. The
// other FindFunctions method should be able to take advantage of any
// accelerator tables available in the debug information (which is
// parsed by the SymbolFile parser plug-ins and registered with each
// Module).
//----------------------------------------------------------------------
//void
//CompileUnit::FindFunctions(const Mangled::Tokens& tokens)
//{
//  if (!m_functions.empty())
//  {
//      Stream s(stdout);
//      std::vector<FunctionSP>::const_iterator pos;
//      std::vector<FunctionSP>::const_iterator end = m_functions.end();
//      for (pos = m_functions.begin(); pos != end; ++pos)
//      {
//          const ConstString& demangled = (*pos)->Mangled().Demangled();
//          if (demangled)
//          {
//              const Mangled::Tokens& func_tokens = (*pos)->Mangled().GetTokens();
//              if (func_tokens.MatchesQuery (tokens))
//                  s << "demangled MATCH found: " << demangled << "\n";
//          }
//      }
//  }
//}

FunctionSP
CompileUnit::FindFunctionByUID (lldb::user_id_t func_uid)
{
    FunctionSP funcSP;
    if (!m_functions.empty())
    {
        std::vector<FunctionSP>::const_iterator pos;
        std::vector<FunctionSP>::const_iterator end = m_functions.end();
        for (pos = m_functions.begin(); pos != end; ++pos)
        {
            if ((*pos)->GetID() == func_uid)
            {
                funcSP = *pos;
                break;
            }
        }
    }
    return funcSP;
}


LineTable*
CompileUnit::GetLineTable()
{
    if (m_line_table_ap.get() == NULL)
    {
        if (m_flags.IsClear(flagsParsedLineTable))
        {
            m_flags.Set(flagsParsedLineTable);
            SymbolVendor* symbol_vendor = GetModule()->GetSymbolVendor();
            if (symbol_vendor)
            {
                SymbolContext sc;
                CalculateSymbolContext(&sc);
                symbol_vendor->ParseCompileUnitLineTable(sc);
            }
        }
    }
    return m_line_table_ap.get();
}

void
CompileUnit::SetLineTable(LineTable* line_table)
{
    if (line_table == NULL)
        m_flags.Clear(flagsParsedLineTable);
    else
        m_flags.Set(flagsParsedLineTable);
    m_line_table_ap.reset(line_table);
}

VariableListSP
CompileUnit::GetVariableList(bool can_create)
{
    if (m_variables.get() == NULL && can_create)
    {
        SymbolContext sc;
        CalculateSymbolContext(&sc);
        assert(sc.module_sp);
        sc.module_sp->GetSymbolVendor()->ParseVariablesForContext(sc);
    }

    return m_variables;
}

uint32_t
CompileUnit::FindLineEntry (uint32_t start_idx, uint32_t line, const FileSpec* file_spec_ptr, LineEntry *line_entry_ptr)
{
    uint32_t file_idx = 0;

    if (file_spec_ptr)
    {
        file_idx = GetSupportFiles().FindFileIndex (1, *file_spec_ptr);
        if (file_idx == UINT32_MAX)
            return UINT32_MAX;
    }
    else
    {
        // All the line table entries actually point to the version of the Compile
        // Unit that is in the support files (the one at 0 was artifically added.)
        // So prefer the one further on in the support files if it exists...
        FileSpecList &support_files = GetSupportFiles();
        file_idx = support_files.FindFileIndex (1, support_files.GetFileSpecAtIndex(0));
        if (file_idx == UINT32_MAX)
            file_idx = 0;
    }
    LineTable *line_table = GetLineTable();
    if (line_table)
        return line_table->FindLineEntryIndexByFileIndex (start_idx, file_idx, line, true, line_entry_ptr);
    return UINT32_MAX;
}




uint32_t
CompileUnit::ResolveSymbolContext
(
    const FileSpec& file_spec,
    uint32_t line,
    bool check_inlines,
    bool exact,
    uint32_t resolve_scope,
    SymbolContextList &sc_list
)
{
    const uint32_t prev_size = sc_list.GetSize();
    bool file_spec_matches_cu_file_spec = FileSpec::Compare(file_spec, this, !file_spec.GetDirectory().IsEmpty()) == 0;
    if (check_inlines || file_spec_matches_cu_file_spec)
    {
        SymbolContext sc(GetModule());
        sc.comp_unit = this;

        uint32_t file_idx = UINT32_MAX;

        // If we are looking for inline functions only and we don't
        // find it in the support files, we are done.

        if (check_inlines)
        {
            file_idx = sc.comp_unit->GetSupportFiles().FindFileIndex (1, file_spec);
            if (file_idx == UINT32_MAX)
                return 0;
        }

        if (line != 0)
        {
            LineTable *line_table = sc.comp_unit->GetLineTable();

            if (line_table != NULL)
            {
                // We will have already looked up the file index if
                // we are searching for inline entries.
                if (!check_inlines)
                    file_idx = sc.comp_unit->GetSupportFiles().FindFileIndex (1, file_spec);

                if (file_idx != UINT32_MAX)
                {
                    uint32_t found_line;

                    uint32_t line_idx = line_table->FindLineEntryIndexByFileIndex (0, file_idx, line, exact, &sc.line_entry);
                    found_line = sc.line_entry.line;

                    while (line_idx != UINT_MAX)
                    {
                        sc_list.Append(sc);
                        line_idx = line_table->FindLineEntryIndexByFileIndex (line_idx + 1, file_idx, found_line, true, &sc.line_entry);
                    }
                }
            }
        }
        else if (file_spec_matches_cu_file_spec && !check_inlines)
        {
            // only append the context if we aren't looking for inline call sites
            // by file and line and if the file spec matches that of the compile unit
            sc_list.Append(sc);
        }

    }
    return sc_list.GetSize() - prev_size;
}

void
CompileUnit::SetVariableList(VariableListSP &variables)
{
    m_variables = variables;
}

FileSpecList&
CompileUnit::GetSupportFiles ()
{
    if (m_support_files.GetSize() == 0)
    {
        if (m_flags.IsClear(flagsParsedSupportFiles))
        {
            m_flags.Set(flagsParsedSupportFiles);
            SymbolVendor* symbol_vendor = GetModule()->GetSymbolVendor();
            if (symbol_vendor)
            {
                SymbolContext sc;
                CalculateSymbolContext(&sc);
                symbol_vendor->ParseCompileUnitSupportFiles(sc, m_support_files);
            }
        }
    }
    return m_support_files;
}

void *
CompileUnit::GetUserData () const
{
    return m_user_data;
}


