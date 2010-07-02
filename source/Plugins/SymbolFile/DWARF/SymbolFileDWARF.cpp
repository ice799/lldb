//===-- SymbolFileDWARF.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "SymbolFileDWARF.h"

// Other libraries and framework includes
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclGroup.h"
#include "clang/Basic/Builtins.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Specifiers.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/RegularExpression.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Core/Section.h"
#include "lldb/Core/Timer.h"
#include "lldb/Core/Value.h"

#include "lldb/Symbol/Block.h"
#include "lldb/Symbol/CompileUnit.h"
#include "lldb/Symbol/LineTable.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Symbol/SymbolVendor.h"
#include "lldb/Symbol/VariableList.h"

#include "DWARFCompileUnit.h"
#include "DWARFDebugAbbrev.h"
#include "DWARFDebugAranges.h"
#include "DWARFDebugInfo.h"
#include "DWARFDebugInfoEntry.h"
#include "DWARFDebugLine.h"
#include "DWARFDebugPubnames.h"
#include "DWARFDebugRanges.h"
#include "DWARFDIECollection.h"
#include "DWARFFormValue.h"
#include "DWARFLocationList.h"
#include "LogChannelDWARF.h"

#include <map>

#define DIE_IS_BEING_PARSED ((void*)1)

using namespace lldb;
using namespace lldb_private;


static const ConstString&
GetSectionNameDebugInfo()
{
    static const ConstString g_sect_name("__debug_info");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugAbbrev()
{
    static const ConstString g_sect_name ("__debug_abbrev");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugAranges()
{
    static const ConstString g_sect_name ("__debug_aranges");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugFrame()
{
    static const ConstString g_sect_name ("__debug_frame");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugLine()
{
    static const ConstString g_sect_name ("__debug_line");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugLoc()
{
    static const ConstString g_sect_name ("__debug_loc");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugMacInfo()
{
    static const ConstString g_sect_name ("__debug_macinfo");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugPubNames()
{
    static const ConstString g_sect_name ("__debug_pubnames");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugPubTypes()
{
    static const ConstString g_sect_name ("__debug_pubtypes");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugRanges()
{
    static const ConstString g_sect_name ("__debug_ranges");
    return g_sect_name;
}

static const ConstString&
GetSectionNameDebugStr()
{
    static const ConstString g_sect_name ("__debug_str");
    return g_sect_name;
}

static uint32_t
DwarfToClangAccessibility (uint32_t dwarf_accessibility)
{
    switch (dwarf_accessibility)
    {
        case DW_ACCESS_public:
            return clang::AS_public;
        case DW_ACCESS_private:
            return clang::AS_private;
        case DW_ACCESS_protected:
            return clang::AS_protected;
        default:
            return clang::AS_none;
    }
}

void
SymbolFileDWARF::Initialize()
{
    LogChannelDWARF::Initialize();
    PluginManager::RegisterPlugin (GetPluginNameStatic(),
                                   GetPluginDescriptionStatic(),
                                   CreateInstance);
}

void
SymbolFileDWARF::Terminate()
{
    PluginManager::UnregisterPlugin (CreateInstance);
    LogChannelDWARF::Initialize();
}


const char *
SymbolFileDWARF::GetPluginNameStatic()
{
    return "symbol-file.dwarf2";
}

const char *
SymbolFileDWARF::GetPluginDescriptionStatic()
{
    return "DWARF and DWARF3 debug symbol file reader.";
}


SymbolFile*
SymbolFileDWARF::CreateInstance (ObjectFile* obj_file)
{
    return new SymbolFileDWARF(obj_file);
}

//----------------------------------------------------------------------
// Gets the first parent that is a lexical block, function or inlined
// subroutine, or compile unit.
//----------------------------------------------------------------------
static const DWARFDebugInfoEntry *
GetParentSymbolContextDIE(const DWARFDebugInfoEntry *child_die)
{
    const DWARFDebugInfoEntry *die;
    for (die = child_die->GetParent(); die != NULL; die = die->GetParent())
    {
        dw_tag_t tag = die->Tag();

        switch (tag)
        {
        case DW_TAG_compile_unit:
        case DW_TAG_subprogram:
        case DW_TAG_inlined_subroutine:
        case DW_TAG_lexical_block:
            return die;
        }
    }
    return NULL;
}


SymbolFileDWARF::SymbolFileDWARF(ObjectFile* ofile) :
    SymbolFile(ofile),
    m_flags(),
    m_data_debug_abbrev(),
    m_data_debug_aranges(),
    m_data_debug_frame(),
    m_data_debug_info(),
    m_data_debug_line(),
    m_data_debug_loc(),
    m_data_debug_macinfo(),
    m_data_debug_pubnames(),
    m_data_debug_pubtypes(),
    m_data_debug_ranges(),
    m_data_debug_str(),
    m_abbr(),
    m_aranges(),
    m_info(),
    m_line(),
    m_base_name_to_function_die(),
    m_full_name_to_function_die(),
    m_method_name_to_function_die(),
    m_selector_name_to_function_die(),
    m_name_to_global_die(),
    m_name_to_type_die(),
    m_indexed(false),
//    m_pubnames(),
//    m_pubtypes(),
//    m_pubbasetypes(),
    m_ranges()//,
//  m_type_fixups(),
//  m_indirect_fixups()
{
}

SymbolFileDWARF::~SymbolFileDWARF()
{
}

bool
SymbolFileDWARF::SupportedVersion(uint16_t version)
{
    return version == 2 || version == 3;
}

uint32_t
SymbolFileDWARF::GetAbilities ()
{
    uint32_t abilities = 0;
    if (m_obj_file != NULL)
    {
        const Section* section = NULL;
        const SectionList *section_list = m_obj_file->GetSectionList();
        if (section_list == NULL)
            return 0;

        uint64_t debug_abbrev_file_size = 0;
        uint64_t debug_aranges_file_size = 0;
        uint64_t debug_frame_file_size = 0;
        uint64_t debug_info_file_size = 0;
        uint64_t debug_line_file_size = 0;
        uint64_t debug_loc_file_size = 0;
        uint64_t debug_macinfo_file_size = 0;
        uint64_t debug_pubnames_file_size = 0;
        uint64_t debug_pubtypes_file_size = 0;
        uint64_t debug_ranges_file_size = 0;
        uint64_t debug_str_file_size = 0;

        static ConstString g_dwarf_section_name ("__DWARF");

        section = section_list->FindSectionByName(g_dwarf_section_name).get();
        
        if (section)
            section->MemoryMapSectionDataFromObjectFile(m_obj_file, m_dwarf_data);
        
        section = section_list->FindSectionByName (GetSectionNameDebugInfo()).get();
        if (section != NULL)
        {
            debug_info_file_size = section->GetByteSize();

            section = section_list->FindSectionByName (GetSectionNameDebugAbbrev()).get();
            if (section)
                debug_abbrev_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugAbbrevData);

            section = section_list->FindSectionByName (GetSectionNameDebugAranges()).get();
            if (section)
                debug_aranges_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugArangesData);

            section = section_list->FindSectionByName (GetSectionNameDebugFrame()).get();
            if (section)
                debug_frame_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugFrameData);

            section = section_list->FindSectionByName (GetSectionNameDebugLine()).get();
            if (section)
                debug_line_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugLineData);

            section = section_list->FindSectionByName (GetSectionNameDebugLoc()).get();
            if (section)
                debug_loc_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugLocData);

            section = section_list->FindSectionByName (GetSectionNameDebugMacInfo()).get();
            if (section)
                debug_macinfo_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugMacInfoData);

            section = section_list->FindSectionByName (GetSectionNameDebugPubNames()).get();
            if (section)
                debug_pubnames_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugPubNamesData);

            section = section_list->FindSectionByName (GetSectionNameDebugPubTypes()).get();
            if (section)
                debug_pubtypes_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugPubTypesData);

            section = section_list->FindSectionByName (GetSectionNameDebugRanges()).get();
            if (section)
                debug_ranges_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugRangesData);

            section = section_list->FindSectionByName (GetSectionNameDebugStr()).get();
            if (section)
                debug_str_file_size = section->GetByteSize();
            else
                m_flags.Set (flagsGotDebugStrData);
        }

        if (debug_abbrev_file_size > 0 && debug_info_file_size > 0)
            abilities |= CompileUnits | Functions | Blocks | GlobalVariables | LocalVariables | VariableTypes;

        if (debug_line_file_size > 0)
            abilities |= LineTables;

        if (debug_aranges_file_size > 0)
            abilities |= AddressAcceleratorTable;

        if (debug_pubnames_file_size > 0)
            abilities |= FunctionAcceleratorTable;

        if (debug_pubtypes_file_size > 0)
            abilities |= TypeAcceleratorTable;

        if (debug_macinfo_file_size > 0)
            abilities |= MacroInformation;

        if (debug_frame_file_size > 0)
            abilities |= CallFrameInformation;
    }
    return abilities;
}

const DataExtractor&
SymbolFileDWARF::GetCachedSectionData (uint32_t got_flag, const ConstString &section_name, DataExtractor &data)
{
    if (m_flags.IsClear (got_flag))
    {
        m_flags.Set (got_flag);
        const SectionList *section_list = m_obj_file->GetSectionList();
        if (section_list)
        {
            Section *section = section_list->FindSectionByName (section_name).get();
            if (section )
            {
                // See if we memory mapped the DWARF segment?
                if (m_dwarf_data.GetByteSize())
                {
                    data.SetData(m_dwarf_data, section->GetOffset (), section->GetByteSize());
                }
                else
                {
                    if (section->ReadSectionDataFromObjectFile(m_obj_file, data) == 0)
                        data.Clear();
                }
            }
        }
    }
    return data;
}

const DataExtractor&
SymbolFileDWARF::get_debug_abbrev_data()
{
    return GetCachedSectionData (flagsGotDebugAbbrevData, GetSectionNameDebugAbbrev(), m_data_debug_abbrev);
}

const DataExtractor&
SymbolFileDWARF::get_debug_aranges_data()
{
    return GetCachedSectionData (flagsGotDebugArangesData, GetSectionNameDebugAranges(), m_data_debug_aranges);
}

const DataExtractor&
SymbolFileDWARF::get_debug_frame_data()
{
    return GetCachedSectionData (flagsGotDebugFrameData, GetSectionNameDebugFrame(), m_data_debug_frame);
}

const DataExtractor&
SymbolFileDWARF::get_debug_info_data()
{
    return GetCachedSectionData (flagsGotDebugInfoData, GetSectionNameDebugInfo(), m_data_debug_info);
}

const DataExtractor&
SymbolFileDWARF::get_debug_line_data()
{
    return GetCachedSectionData (flagsGotDebugLineData, GetSectionNameDebugLine(), m_data_debug_line);
}

const DataExtractor&
SymbolFileDWARF::get_debug_loc_data()
{
    return GetCachedSectionData (flagsGotDebugLocData, GetSectionNameDebugLoc(), m_data_debug_loc);
}

const DataExtractor&
SymbolFileDWARF::get_debug_macinfo_data()
{
    return GetCachedSectionData (flagsGotDebugMacInfoData, GetSectionNameDebugMacInfo(), m_data_debug_macinfo);
}

const DataExtractor&
SymbolFileDWARF::get_debug_pubnames_data()
{
    return GetCachedSectionData (flagsGotDebugPubNamesData, GetSectionNameDebugPubNames(), m_data_debug_pubnames);
}

const DataExtractor&
SymbolFileDWARF::get_debug_pubtypes_data()
{
    return GetCachedSectionData (flagsGotDebugPubTypesData, GetSectionNameDebugPubTypes(), m_data_debug_pubtypes);
}

const DataExtractor&
SymbolFileDWARF::get_debug_ranges_data()
{
    return GetCachedSectionData (flagsGotDebugRangesData, GetSectionNameDebugRanges(), m_data_debug_ranges);
}

const DataExtractor&
SymbolFileDWARF::get_debug_str_data()
{
    return GetCachedSectionData (flagsGotDebugStrData, GetSectionNameDebugStr(), m_data_debug_str);
}


DWARFDebugAbbrev*
SymbolFileDWARF::DebugAbbrev()
{
    if (m_abbr.get() == NULL)
    {
        const DataExtractor &debug_abbrev_data = get_debug_abbrev_data();
        if (debug_abbrev_data.GetByteSize() > 0)
        {
            m_abbr.reset(new DWARFDebugAbbrev());
            if (m_abbr.get())
                m_abbr->Parse(debug_abbrev_data);
        }
    }
    return m_abbr.get();
}

const DWARFDebugAbbrev*
SymbolFileDWARF::DebugAbbrev() const
{
    return m_abbr.get();
}

DWARFDebugAranges*
SymbolFileDWARF::DebugAranges()
{
    if (m_aranges.get() == NULL)
    {
        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
        m_aranges.reset(new DWARFDebugAranges());
        if (m_aranges.get())
        {
            const DataExtractor &debug_aranges_data = get_debug_aranges_data();
            if (debug_aranges_data.GetByteSize() > 0)
                m_aranges->Extract(debug_aranges_data);
            else
                m_aranges->Generate(this);
        }
    }
    return m_aranges.get();
}

const DWARFDebugAranges*
SymbolFileDWARF::DebugAranges() const
{
    return m_aranges.get();
}


DWARFDebugInfo*
SymbolFileDWARF::DebugInfo()
{
    if (m_info.get() == NULL)
    {
        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
        if (get_debug_info_data().GetByteSize() > 0)
        {
            m_info.reset(new DWARFDebugInfo());
            if (m_info.get())
            {
                m_info->SetDwarfData(this);
            }
        }
    }
    return m_info.get();
}

const DWARFDebugInfo*
SymbolFileDWARF::DebugInfo() const
{
    return m_info.get();
}

//DWARFDebugLine*
//SymbolFileDWARF::DebugLine()
//{
//  if (m_line.get() == NULL)
//  {
//      Timer scoped_timer(__PRETTY_FUNCTION__);
//      const DataExtractor &debug_line_data = debug_line();
//      if (debug_line_data.GetByteSize() > 0)
//      {
//          m_line.reset(new DWARFDebugLine());
//          if (m_line.get())
//              m_line->Parse(debug_line_data);
//      }
//  }
//  return m_line.get();
//}
//
//const DWARFDebugLine*
//SymbolFileDWARF::DebugLine() const
//{
//  return m_line.get();
//}


DWARFCompileUnit*
SymbolFileDWARF::GetDWARFCompileUnitForUID(lldb::user_id_t cu_uid)
{
    DWARFDebugInfo* info = DebugInfo();
    if (info)
        return info->GetCompileUnit(cu_uid).get();
    return NULL;
}

//DWARFCompileUnit*
//SymbolFileDWARF::GetNextUnparsedDWARFCompileUnit(DWARFCompileUnit* prev_cu)
//{
//  DWARFCompileUnit* cu = NULL;
//  DWARFDebugInfo* info = DebugInfo();
//  if (info)
//  {
//      uint32_t cu_idx = 0;
//      if (prev_cu != NULL)
//      {
//          // Find the index of the previus DWARF compile unit if one was provided
//          while ((cu = info->GetCompileUnitAtIndex(cu_idx)) != NULL)
//          {
//              ++cu_idx;
//              if (cu == prev_cu)
//                  break;
//          }
//      }
//
//      // Now find the next unparsed DWARF compile unit. We do this by checking the
//      // user data in the DWARFCompileUnit class that starts as NULL, and eventually
//      // holds a pointer to the CompileUnit that was created for it after it has
//      // been parsed.
//      while ((cu = info->GetCompileUnitAtIndex(cu_idx)) != NULL)
//      {
//          if (cu->GetUserData() == NULL)
//              break;
//      }
//  }
//  return cu;
//}

DWARFDebugRanges*
SymbolFileDWARF::DebugRanges()
{
    if (m_ranges.get() == NULL)
    {
        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
        if (get_debug_ranges_data().GetByteSize() > 0)
        {
            m_ranges.reset(new DWARFDebugRanges());
            if (m_ranges.get())
                m_ranges->Extract(this);
        }
    }
    return m_ranges.get();
}

const DWARFDebugRanges*
SymbolFileDWARF::DebugRanges() const
{
    return m_ranges.get();
}
//
//DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubnames()
//{
//    if (m_pubnames.get() == NULL)
//    {
//        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
//        const DataExtractor &debug_pubnames_data = get_debug_pubnames_data();
//        if (debug_pubnames_data.GetByteSize() > 0)
//        {
//            // Pass false to indicate this is a pubnames section
//            m_pubnames.reset(new DWARFDebugPubnames());
//            if (m_pubnames.get())
//            {
//                // "m_pubnames->GeneratePubnames" is costly, but needed for global variables
//                m_pubnames->GeneratePubnames(this);
//
//#if 0
//                StreamFile s(stdout);
//                s.Printf (".debug_pubnames for %s/%s:\n",
//                          m_obj_file->GetModule()->GetFileSpec().GetDirectory().AsCString(),
//                          m_obj_file->GetModule()->GetFileSpec().GetFilename().AsCString());
//                m_pubnames->Dump (&s);
//#endif
//                // "m_pubnames->Extract" is quicker, but the pubnames don't always contain what we need.
//                //m_pubnames->Extract(debug_pubnames_data);
//            }
//        }
//    }
//    return m_pubnames.get();
//}
//
//const DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubnames() const
//{
//    return m_pubnames.get();
//}

//DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubBaseTypes()
//{
//    if (m_pubbasetypes.get() == NULL)
//    {
//        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
//        // Pass false to indicate this is a pubnames section
//        m_pubbasetypes.reset(new DWARFDebugPubnames());
//        if (m_pubbasetypes.get())
//            m_pubbasetypes->GeneratePubBaseTypes(this);
//    }
//    return m_pubbasetypes.get();
//}
//
//const DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubBaseTypes() const
//{
//    return m_pubbasetypes.get();
//}
//
//const DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubtypes() const
//{
//    return m_pubtypes.get();
//}
//
//DWARFDebugPubnames*
//SymbolFileDWARF::DebugPubtypes()
//{
//    if (m_pubtypes.get() == NULL)
//    {
//        Timer scoped_timer(__PRETTY_FUNCTION__, "%s this = %p", __PRETTY_FUNCTION__, this);
//        const DataExtractor &debug_pubtypes_data = get_debug_pubtypes_data();
//        if (debug_pubtypes_data.GetByteSize() > 0)
//        {
//            // Pass false to indicate this is a pubnames section
//            m_pubtypes.reset(new DWARFDebugPubnames());
//            if (m_pubtypes.get())
//                m_pubtypes->Extract(debug_pubtypes_data);
//        }
//    }
//    return m_pubtypes.get();
//}
//

bool
SymbolFileDWARF::ParseCompileUnit(DWARFCompileUnit* cu, CompUnitSP& compile_unit_sp)
{
    if (cu != NULL)
    {
        const DWARFDebugInfoEntry * cu_die = cu->GetCompileUnitDIEOnly ();
        if (cu_die)
        {
            const char * cu_die_name = cu_die->GetName(this, cu);
            const char * cu_comp_dir = cu_die->GetAttributeValueAsString(this, cu, DW_AT_comp_dir, NULL);
            Language::Type language = (Language::Type)cu_die->GetAttributeValueAsUnsigned(this, cu, DW_AT_language, 0);
            if (cu_die_name)
            {
                if (cu_die_name[0] == '/' || cu_comp_dir == NULL && cu_comp_dir[0])
                {
                    compile_unit_sp.reset(new CompileUnit(m_obj_file->GetModule(), cu, cu_die_name, cu->GetOffset(), language));
                }
                else
                {
                    std::string fullpath(cu_comp_dir);
                    if (*fullpath.rbegin() != '/')
                        fullpath += '/';
                    fullpath += cu_die_name;

                    compile_unit_sp.reset(new CompileUnit(m_obj_file->GetModule(), cu, fullpath.c_str(), cu->GetOffset(), language));
                }

                if (compile_unit_sp.get())
                {
                    cu->SetUserData(compile_unit_sp.get());
                    return true;
                }
            }
        }
    }
    return false;
}

#if defined LLDB_SYMBOL_FILE_DWARF_SHRINK_TEST

void
SymbolFileDWARF::ShrinkDSYM(CompileUnit *dc_cu, DWARFCompileUnit *dw_cu, const FileSpec& cu_fspec, const FileSpec& base_types_fspec, FSToDIES& fs_to_dies, const DWARFDebugInfoEntry *die)
{
    while (die != NULL)
    {
        dw_tag_t tag = die->Tag();

        switch (tag)
        {
        case DW_TAG_base_type:
            // Put all base types into the base type compile unit
            fs_to_dies[base_types_fspec].Insert(die);
            break;

        default:
            {
                uint32_t decl_file = die->GetAttributeValueAsUnsigned(this, dw_cu, DW_AT_decl_file, 0);
                if (decl_file)
                {
                    fs_to_dies[dc_cu->GetSupportFiles().GetFileSpecAtIndex(decl_file)].Insert(die);
                }
                else
                {
                    // add this to the current compile unit
                    fs_to_dies[cu_fspec].Insert(die);
                }
            }
            break;
        }

        die = die->GetSibling();
    }
}



#endif

uint32_t
SymbolFileDWARF::GetNumCompileUnits()
{
    DWARFDebugInfo* info = DebugInfo();
    if (info)
    {
#if defined LLDB_SYMBOL_FILE_DWARF_SHRINK_TEST
        uint32_t cu_idx;
        FSToDIES fs_to_dies;

        FileSpec base_type_fspec("DW_TAG_base_type");
        const uint32_t num_comp_units = info->GetNumCompileUnits();

        for (cu_idx=0; cu_idx < num_comp_units; ++cu_idx)
        {
            DWARFCompileUnit* cu = info->GetCompileUnitAtIndex(cu_idx);
            if (cu != NULL)
            {
                const DWARFDebugInfoEntry *cu_die = cu->DIE();
                if (cu_die)
                {
                    CompUnitSP dc_cu_sp;
                    ParseCompileUnit(cu, dc_cu_sp);
                    if (dc_cu_sp.get())
                    {
                        FileSpec cu_fspec(*dc_cu_sp.get());

                        ShrinkDSYM(dc_cu_sp.get(), cu, cu_fspec, base_type_fspec, fs_to_dies, cu->DIE()->GetFirstChild());
                    }
                }
            }
        }

        Stream strm(stdout);
        FSToDIES::const_iterator pos, end = fs_to_dies.end();
        for (pos = fs_to_dies.begin(); pos != end; ++pos)
        {
            strm << "\n\nMinimal Compile Unit: " << pos->first << ":\n";
            const DWARFDIECollection& dies = pos->second;
            dies.Dump(strm, NULL);
        }
        return num_comp_units;
#else
        return info->GetNumCompileUnits();
#endif
    }
    return 0;
}

CompUnitSP
SymbolFileDWARF::ParseCompileUnitAtIndex(uint32_t cu_idx)
{
    CompUnitSP comp_unit;
    DWARFDebugInfo* info = DebugInfo();
    if (info)
    {
        DWARFCompileUnit* cu = info->GetCompileUnitAtIndex(cu_idx);
        if (cu != NULL)
        {
            // Our symbol vendor shouldn't be asking us to add a compile unit that
            // has already been added to it, which this DWARF plug-in knows as it
            // stores the lldb compile unit (CompileUnit) pointer in each
            // DWARFCompileUnit object when it gets added.
            assert(cu->GetUserData() == NULL);
            ParseCompileUnit(cu, comp_unit);
        }
    }
    return comp_unit;
}

static void
AddRangesToBlock
(
    BlockList& blocks,
    lldb::user_id_t blockID,
    DWARFDebugRanges::RangeList& ranges,
    addr_t block_base_addr
)
{
    ranges.SubtractOffset (block_base_addr);
    size_t range_idx = 0;
    const DWARFDebugRanges::Range *debug_range;
    for (range_idx = 0; (debug_range = ranges.RangeAtIndex(range_idx)) != NULL; range_idx++)
    {
        blocks.AddRange(blockID, debug_range->begin_offset, debug_range->end_offset);
    }
}


Function *
SymbolFileDWARF::ParseCompileUnitFunction (const SymbolContext& sc, const DWARFCompileUnit* dwarf_cu, const DWARFDebugInfoEntry *die)
{
    DWARFDebugRanges::RangeList func_ranges;
    const char *name = NULL;
    const char *mangled = NULL;
    int decl_file = 0;
    int decl_line = 0;
    int decl_column = 0;
    int call_file = 0;
    int call_line = 0;
    int call_column = 0;
    DWARFExpression frame_base;

    // Parse the function prototype as a type that can then be added to concrete function instance
    ParseTypes (sc, dwarf_cu, die, false, false);
    //FixupTypes();

    if (die->GetDIENamesAndRanges(this, dwarf_cu, name, mangled, func_ranges, decl_file, decl_line, decl_column, call_file, call_line, call_column, &frame_base))
    {
        // Union of all ranges in the function DIE (if the function is discontiguous)
        AddressRange func_range;
        lldb::addr_t lowest_func_addr = func_ranges.LowestAddress(0);
        lldb::addr_t highest_func_addr = func_ranges.HighestAddress(0);
        if (lowest_func_addr != LLDB_INVALID_ADDRESS && lowest_func_addr <= highest_func_addr)
        {
            func_range.GetBaseAddress().ResolveAddressUsingFileSections (lowest_func_addr, m_obj_file->GetSectionList());
            if (func_range.GetBaseAddress().IsValid())
                func_range.SetByteSize(highest_func_addr - lowest_func_addr);
        }

        if (func_range.GetBaseAddress().IsValid())
        {
            Mangled func_name;
            if (mangled)
                func_name.SetValue(mangled, true);
            else if (name)
                func_name.SetValue(name, false);

            FunctionSP func_sp;
            std::auto_ptr<Declaration> decl_ap;
            if (decl_file != 0 || decl_line != 0 || decl_column != 0)
                decl_ap.reset(new Declaration(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(decl_file), decl_line, decl_column));

            Type *func_type = NULL;

            if (die->GetUserData() != DIE_IS_BEING_PARSED)
                func_type = (Type*)die->GetUserData();

            assert(func_type == NULL || func_type != DIE_IS_BEING_PARSED);

            func_range.GetBaseAddress().ResolveLinkedAddress();

            func_sp.reset(new Function (sc.comp_unit,
                                        die->GetOffset(),       // UserID is the DIE offset
                                        die->GetOffset(),
                                        func_name,
                                        func_type,
                                        func_range));           // first address range

            if (func_sp.get() != NULL)
            {
                func_sp->GetFrameBaseExpression() = frame_base;
                sc.comp_unit->AddFunction(func_sp);
                return func_sp.get();
            }
        }
    }
    return NULL;
}

size_t
SymbolFileDWARF::ParseCompileUnitFunctions(const SymbolContext &sc)
{
    assert (sc.comp_unit);
    size_t functions_added = 0;
    const DWARFCompileUnit* dwarf_cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());
    if (dwarf_cu)
    {
        DWARFDIECollection function_dies;
        const size_t num_funtions = dwarf_cu->AppendDIEsWithTag (DW_TAG_subprogram, function_dies);
        size_t func_idx;
        for (func_idx = 0; func_idx < num_funtions; ++func_idx)
        {
            const DWARFDebugInfoEntry *die = function_dies.GetDIEPtrAtIndex(func_idx);
            if (sc.comp_unit->FindFunctionByUID (die->GetOffset()).get() == NULL)
            {
                if (ParseCompileUnitFunction(sc, dwarf_cu, die))
                    ++functions_added;
            }
        }
        //FixupTypes();
    }
    return functions_added;
}

bool
SymbolFileDWARF::ParseCompileUnitSupportFiles (const SymbolContext& sc, FileSpecList& support_files)
{
    assert (sc.comp_unit);
    DWARFCompileUnit* cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());
    assert (cu);
    const DWARFDebugInfoEntry * cu_die = cu->GetCompileUnitDIEOnly();

    if (cu_die)
    {
        const char * cu_comp_dir = cu_die->GetAttributeValueAsString(this, cu, DW_AT_comp_dir, NULL);
        dw_offset_t stmt_list = cu_die->GetAttributeValueAsUnsigned(this, cu, DW_AT_stmt_list, DW_INVALID_OFFSET);

        // All file indexes in DWARF are one based and a file of index zero is
        // supposed to be the compile unit itself.
        support_files.Append (*sc.comp_unit);

        return DWARFDebugLine::ParseSupportFiles(get_debug_line_data(), cu_comp_dir, stmt_list, support_files);
    }
    return false;
}

struct ParseDWARFLineTableCallbackInfo
{
    LineTable* line_table;
    const SectionList *section_list;
    lldb::addr_t prev_sect_file_base_addr;
    lldb::addr_t curr_sect_file_base_addr;
    bool is_oso_for_debug_map;
    bool prev_in_final_executable;
    DWARFDebugLine::Row prev_row;
    SectionSP prev_section_sp;
    SectionSP curr_section_sp;
};

//----------------------------------------------------------------------
// ParseStatementTableCallback
//----------------------------------------------------------------------
static void
ParseDWARFLineTableCallback(dw_offset_t offset, const DWARFDebugLine::State& state, void* userData)
{
    LineTable* line_table = ((ParseDWARFLineTableCallbackInfo*)userData)->line_table;
    if (state.row == DWARFDebugLine::State::StartParsingLineTable)
    {
        // Just started parsing the line table
    }
    else if (state.row == DWARFDebugLine::State::DoneParsingLineTable)
    {
        // Done parsing line table, nothing to do for the cleanup
    }
    else
    {
        ParseDWARFLineTableCallbackInfo* info = (ParseDWARFLineTableCallbackInfo*)userData;
        // We have a new row, lets append it

        if (info->curr_section_sp.get() == NULL || info->curr_section_sp->ContainsFileAddress(state.address) == false)
        {
            info->prev_section_sp = info->curr_section_sp;
            info->prev_sect_file_base_addr = info->curr_sect_file_base_addr;
            // If this is an end sequence entry, then we subtract one from the
            // address to make sure we get an address that is not the end of
            // a section.
            if (state.end_sequence && state.address != 0)
                info->curr_section_sp = info->section_list->FindSectionContainingFileAddress (state.address - 1);
            else
                info->curr_section_sp = info->section_list->FindSectionContainingFileAddress (state.address);

            if (info->curr_section_sp.get())
                info->curr_sect_file_base_addr = info->curr_section_sp->GetFileAddress ();
            else
                info->curr_sect_file_base_addr = 0;
        }
        if (info->curr_section_sp.get())
        {
            lldb::addr_t curr_line_section_offset = state.address - info->curr_sect_file_base_addr;
            // Check for the fancy section magic to determine if we

            if (info->is_oso_for_debug_map)
            {
                // When this is a debug map object file that contains DWARF
                // (referenced from an N_OSO debug map nlist entry) we will have
                // a file address in the file range for our section from the
                // original .o file, and a load address in the executable that
                // contains the debug map.
                //
                // If the sections for the file range and load range are
                // different, we have a remapped section for the function and
                // this address is resolved. If they are the same, then the
                // function for this address didn't make it into the final
                // executable.
                bool curr_in_final_executable = info->curr_section_sp->GetLinkedSection () != NULL;

                // If we are doing DWARF with debug map, then we need to carefully
                // add each line table entry as there may be gaps as functions
                // get moved around or removed.
                if (!info->prev_row.end_sequence && info->prev_section_sp.get())
                {
                    if (info->prev_in_final_executable)
                    {
                        bool terminate_previous_entry = false;
                        if (!curr_in_final_executable)
                        {
                            // Check for the case where the previous line entry
                            // in a function made it into the final executable,
                            // yet the current line entry falls in a function
                            // that didn't. The line table used to be contiguous
                            // through this address range but now it isn't. We
                            // need to terminate the previous line entry so
                            // that we can reconstruct the line range correctly
                            // for it and to keep the line table correct.
                            terminate_previous_entry = true;
                        }
                        else if (info->curr_section_sp.get() != info->prev_section_sp.get())
                        {
                            // Check for cases where the line entries used to be
                            // contiguous address ranges, but now they aren't.
                            // This can happen when order files specify the
                            // ordering of the functions.
                            lldb::addr_t prev_line_section_offset = info->prev_row.address - info->prev_sect_file_base_addr;
                            Section *curr_sect = info->curr_section_sp.get();
                            Section *prev_sect = info->prev_section_sp.get();
                            assert (curr_sect->GetLinkedSection());
                            assert (prev_sect->GetLinkedSection());
                            lldb::addr_t object_file_addr_delta = state.address - info->prev_row.address;
                            lldb::addr_t curr_linked_file_addr = curr_sect->GetLinkedFileAddress() + curr_line_section_offset;
                            lldb::addr_t prev_linked_file_addr = prev_sect->GetLinkedFileAddress() + prev_line_section_offset;
                            lldb::addr_t linked_file_addr_delta = curr_linked_file_addr - prev_linked_file_addr;
                            if (object_file_addr_delta != linked_file_addr_delta)
                                terminate_previous_entry = true;
                        }

                        if (terminate_previous_entry)
                        {
                            line_table->InsertLineEntry (info->prev_section_sp,
                                                         state.address - info->prev_sect_file_base_addr,
                                                         info->prev_row.line,
                                                         info->prev_row.column,
                                                         info->prev_row.file,
                                                         false,                 // is_stmt
                                                         false,                 // basic_block
                                                         false,                 // state.prologue_end
                                                         false,                 // state.epilogue_begin
                                                         true);                 // end_sequence);
                        }
                    }
                }

                if (curr_in_final_executable)
                {
                    line_table->InsertLineEntry (info->curr_section_sp,
                                                 curr_line_section_offset,
                                                 state.line,
                                                 state.column,
                                                 state.file,
                                                 state.is_stmt,
                                                 state.basic_block,
                                                 state.prologue_end,
                                                 state.epilogue_begin,
                                                 state.end_sequence);
                    info->prev_section_sp = info->curr_section_sp;
                }
                else
                {
                    // If the current address didn't make it into the final
                    // executable, the current section will be the __text
                    // segment in the .o file, so we need to clear this so
                    // we can catch the next function that did make it into
                    // the final executable.
                    info->prev_section_sp.reset();
                    info->curr_section_sp.reset();
                }

                info->prev_in_final_executable = curr_in_final_executable;
            }
            else
            {
                // We are not in an object file that contains DWARF for an
                // N_OSO, this is just a normal DWARF file. The DWARF spec
                // guarantees that the addresses will be in increasing order
                // so, since we store line tables in file address order, we
                // can always just append the line entry without needing to
                // search for the correct insertion point (we don't need to
                // use LineEntry::InsertLineEntry()).
                line_table->AppendLineEntry (info->curr_section_sp,
                                             curr_line_section_offset,
                                             state.line,
                                             state.column,
                                             state.file,
                                             state.is_stmt,
                                             state.basic_block,
                                             state.prologue_end,
                                             state.epilogue_begin,
                                             state.end_sequence);
            }
        }

        info->prev_row = state;
    }
}

bool
SymbolFileDWARF::ParseCompileUnitLineTable (const SymbolContext &sc)
{
    assert (sc.comp_unit);
    if (sc.comp_unit->GetLineTable() != NULL)
        return true;

    DWARFCompileUnit* dwarf_cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());
    if (dwarf_cu)
    {
        const DWARFDebugInfoEntry *dwarf_cu_die = dwarf_cu->GetCompileUnitDIEOnly();
        const dw_offset_t cu_line_offset = dwarf_cu_die->GetAttributeValueAsUnsigned(this, dwarf_cu, DW_AT_stmt_list, DW_INVALID_OFFSET);
        if (cu_line_offset != DW_INVALID_OFFSET)
        {
            std::auto_ptr<LineTable> line_table_ap(new LineTable(sc.comp_unit));
            if (line_table_ap.get())
            {
                ParseDWARFLineTableCallbackInfo info = { line_table_ap.get(), m_obj_file->GetSectionList(), 0, 0, m_flags.IsSet (flagsDWARFIsOSOForDebugMap), false};
                uint32_t offset = cu_line_offset;
                DWARFDebugLine::ParseStatementTable(get_debug_line_data(), &offset, ParseDWARFLineTableCallback, &info);
                sc.comp_unit->SetLineTable(line_table_ap.release());
                return true;
            }
        }
    }
    return false;
}

size_t
SymbolFileDWARF::ParseFunctionBlocks
(
    const SymbolContext& sc,
    lldb::user_id_t parentBlockID,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *die,
    addr_t subprogram_low_pc,
    bool parse_siblings,
    bool parse_children
)
{
    size_t blocks_added = 0;
    while (die != NULL)
    {
        dw_tag_t tag = die->Tag();

        switch (tag)
        {
        case DW_TAG_subprogram:
        case DW_TAG_inlined_subroutine:
        case DW_TAG_lexical_block:
            {
                DWARFDebugRanges::RangeList ranges;
                const char *name = NULL;
                const char *mangled_name = NULL;
                BlockList& blocks = sc.function->GetBlocks(false);

                lldb::user_id_t blockID = blocks.AddChild(parentBlockID, die->GetOffset());
                int decl_file = 0;
                int decl_line = 0;
                int decl_column = 0;
                int call_file = 0;
                int call_line = 0;
                int call_column = 0;
                if (die->GetDIENamesAndRanges(this, dwarf_cu, name, mangled_name, ranges, decl_file, decl_line, decl_column, call_file, call_line, call_column))
                {
                    if (tag == DW_TAG_subprogram)
                    {
                        assert (subprogram_low_pc == LLDB_INVALID_ADDRESS);
                        subprogram_low_pc = ranges.LowestAddress(0);
                    }

                    AddRangesToBlock (blocks, blockID, ranges, subprogram_low_pc);

                    if (tag != DW_TAG_subprogram && (name != NULL || mangled_name != NULL))
                    {
                        std::auto_ptr<Declaration> decl_ap;
                        if (decl_file != 0 || decl_line != 0 || decl_column != 0)
                            decl_ap.reset(new Declaration(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(decl_file), decl_line, decl_column));

                        std::auto_ptr<Declaration> call_ap;
                        if (call_file != 0 || call_line != 0 || call_column != 0)
                            call_ap.reset(new Declaration(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(call_file), call_line, call_column));

                        blocks.SetInlinedFunctionInfo(blockID, name, mangled_name, decl_ap.get(), call_ap.get());
                    }

                    ++blocks_added;

                    if (parse_children && die->HasChildren())
                    {
                        blocks_added += ParseFunctionBlocks(sc, blockID, dwarf_cu, die->GetFirstChild(), subprogram_low_pc, true, true);
                    }
                }
            }
            break;
        default:
            break;
        }

        if (parse_siblings)
            die = die->GetSibling();
        else
            die = NULL;
    }
    return blocks_added;
}

size_t
SymbolFileDWARF::ParseChildMembers
(
    const SymbolContext& sc,
    TypeSP& type_sp,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *parent_die,
    std::vector<clang::CXXBaseSpecifier *>& base_classes,
    std::vector<int>& member_accessibilities,
    int& default_accessibility,
    bool &is_a_class
)
{
    if (parent_die == NULL)
        return 0;

    TypeList* type_list = m_obj_file->GetModule()->GetTypeList();

    size_t count = 0;
    const DWARFDebugInfoEntry *die;
    for (die = parent_die->GetFirstChild(); die != NULL; die = die->GetSibling())
    {
        dw_tag_t tag = die->Tag();

        switch (tag)
        {
        case DW_TAG_member:
            {
                DWARFDebugInfoEntry::Attributes attributes;
                const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                if (num_attributes > 0)
                {
                    Declaration decl;
                    DWARFExpression location;
                    const char *name = NULL;
                    lldb::user_id_t encoding_uid = LLDB_INVALID_UID;
                    uint32_t accessibility = clang::AS_none;
                    off_t member_offset = 0;
                    size_t byte_size = 0;
                    size_t bit_offset = 0;
                    size_t bit_size = 0;
                    uint32_t i;
                    for (i=0; i<num_attributes; ++i)
                    {
                        const dw_attr_t attr = attributes.AttributeAtIndex(i);
                        DWARFFormValue form_value;
                        if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                        {
                            switch (attr)
                            {
                            case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                            case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                            case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                            case DW_AT_name:        name = form_value.AsCString(&get_debug_str_data()); break;
                            case DW_AT_type:        encoding_uid = form_value.Reference(dwarf_cu); break;
                            case DW_AT_bit_offset:  bit_offset = form_value.Unsigned(); break;
                            case DW_AT_bit_size:    bit_size = form_value.Unsigned(); break;
                            case DW_AT_byte_size:   byte_size = form_value.Unsigned(); break;
                            case DW_AT_data_member_location:
                                if (form_value.BlockData())
                                {
                                    Value initialValue(0);
                                    Value memberOffset(0);
                                    const DataExtractor& debug_info_data = get_debug_info_data();
                                    uint32_t block_length = form_value.Unsigned();
                                    uint32_t block_offset = form_value.BlockData() - debug_info_data.GetDataStart();
                                    if (DWARFExpression::Evaluate(NULL, NULL, debug_info_data, NULL, NULL, block_offset, block_length, eRegisterKindDWARF, &initialValue, memberOffset, NULL))
                                    {
                                        member_offset = memberOffset.ResolveValue(NULL, NULL).UInt();
                                    }
                                }
                                break;

                            case DW_AT_accessibility: accessibility = DwarfToClangAccessibility (form_value.Unsigned()); break;
                            case DW_AT_declaration:
                            case DW_AT_description:
                            case DW_AT_mutable:
                            case DW_AT_visibility:
                            default:
                            case DW_AT_sibling:
                                break;
                            }
                        }
                    }

                    Type *member_type = ResolveTypeUID(encoding_uid);
                    assert(member_type);
                    if (accessibility == clang::AS_none)
                        accessibility = default_accessibility;
                    member_accessibilities.push_back(accessibility);

                    type_list->GetClangASTContext().AddFieldToRecordType (type_sp->GetOpaqueClangQualType(), name, member_type->GetOpaqueClangQualType(), accessibility, bit_size);
                }
            }
            break;

        case DW_TAG_subprogram:
            {
                is_a_class = true;
                if (default_accessibility == clang::AS_none)
                    default_accessibility = clang::AS_private;
                // TODO: implement DW_TAG_subprogram type parsing
//              UserDefTypeChildInfo method_info(die->GetOffset());
//
//              FunctionSP func_sp (sc.comp_unit->FindFunctionByUID (die->GetOffset()));
//              if (func_sp.get() == NULL)
//                  ParseCompileUnitFunction(sc, dwarf_cu, die);
//
//              method_info.SetEncodingTypeUID(die->GetOffset());
//              struct_udt->AddMethod(method_info);
            }
            break;

        case DW_TAG_inheritance:
            {
                is_a_class = true;
                if (default_accessibility == clang::AS_none)
                    default_accessibility = clang::AS_private;
                // TODO: implement DW_TAG_inheritance type parsing
                DWARFDebugInfoEntry::Attributes attributes;
                const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                if (num_attributes > 0)
                {
                    Declaration decl;
                    DWARFExpression location;
                    lldb::user_id_t encoding_uid = LLDB_INVALID_UID;
                    uint32_t accessibility = default_accessibility;
                    bool is_virtual = false;
                    bool is_base_of_class = true;
                    off_t member_offset = 0;
                    uint32_t i;
                    for (i=0; i<num_attributes; ++i)
                    {
                        const dw_attr_t attr = attributes.AttributeAtIndex(i);
                        DWARFFormValue form_value;
                        if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                        {
                            switch (attr)
                            {
                            case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                            case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                            case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                            case DW_AT_type:        encoding_uid = form_value.Reference(dwarf_cu); break;
                            case DW_AT_data_member_location:
                                if (form_value.BlockData())
                                {
                                    Value initialValue(0);
                                    Value memberOffset(0);
                                    const DataExtractor& debug_info_data = get_debug_info_data();
                                    uint32_t block_length = form_value.Unsigned();
                                    uint32_t block_offset = form_value.BlockData() - debug_info_data.GetDataStart();
                                    if (DWARFExpression::Evaluate(NULL, NULL, debug_info_data, NULL, NULL, block_offset, block_length, eRegisterKindDWARF, &initialValue, memberOffset, NULL))
                                    {
                                        member_offset = memberOffset.ResolveValue(NULL, NULL).UInt();
                                    }
                                }
                                break;

                            case DW_AT_accessibility:
                                accessibility = DwarfToClangAccessibility(form_value.Unsigned());
                                break;

                            case DW_AT_virtuality: is_virtual = form_value.Unsigned() != 0; break;
                            default:
                            case DW_AT_sibling:
                                break;
                            }
                        }
                    }

                    Type *base_class_dctype = ResolveTypeUID(encoding_uid);
                    assert(base_class_dctype);
                    base_classes.push_back (type_list->GetClangASTContext().CreateBaseClassSpecifier (base_class_dctype->GetOpaqueClangQualType(), accessibility, is_virtual, is_base_of_class));
                    assert(base_classes.back());
                }
            }
            break;

        default:
            break;
        }
    }
    return count;
}


clang::DeclContext*
SymbolFileDWARF::GetClangDeclContextForTypeUID (lldb::user_id_t type_uid)
{
    DWARFDebugInfo* debug_info = DebugInfo();
    if (debug_info)
    {
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = debug_info->GetDIEPtr(type_uid, &cu_sp);
        if (die)
            return GetClangDeclContextForDIE (cu_sp.get(), die);
    }
    return NULL;
}

Type*
SymbolFileDWARF::ResolveTypeUID(lldb::user_id_t type_uid)
{
    DWARFDebugInfo* debug_info = DebugInfo();
    if (debug_info)
    {
        const DWARFDebugInfoEntry* type_die = debug_info->GetDIEPtr(type_uid, NULL);
        if (type_die != NULL)
        {
            void *type = type_die->GetUserData();
            if (type == NULL)
            {
                DWARFCompileUnitSP cu_sp;
                const DWARFDebugInfoEntry* die = debug_info->GetDIEPtr(type_uid, &cu_sp);
                if (die != NULL)
                {
                    TypeSP owning_type_sp;
                    TypeSP type_sp(GetTypeForDIE(cu_sp.get(), die, owning_type_sp, 0, 0));
                }
                type = type_die->GetUserData();
            }
            if (type != DIE_IS_BEING_PARSED)
                return (Type *)type;
        }
    }
    return NULL;
}

CompileUnit*
SymbolFileDWARF::GetCompUnitForDWARFCompUnit(DWARFCompileUnit* cu, uint32_t cu_idx)
{
    // Check if the symbol vendor already knows about this compile unit?
    if (cu->GetUserData() == NULL)
    {
        // The symbol vendor doesn't know about this compile unit, we
        // need to parse and add it to the symbol vendor object.
        CompUnitSP dc_cu;
        ParseCompileUnit(cu, dc_cu);
        if (dc_cu.get())
        {
            // Figure out the compile unit index if we weren't given one
            if (cu_idx == UINT_MAX)
                DebugInfo()->GetCompileUnit(cu->GetOffset(), &cu_idx);

            m_obj_file->GetModule()->GetSymbolVendor()->SetCompileUnitAtIndex(dc_cu, cu_idx);
        }
    }
    return (CompileUnit*)cu->GetUserData();
}

bool
SymbolFileDWARF::GetFunction (DWARFCompileUnit* cu, const DWARFDebugInfoEntry* func_die, SymbolContext& sc)
{
    sc.Clear();
    // Check if the symbol vendor already knows about this compile unit?
    sc.module_sp = m_obj_file->GetModule()->GetSP();
    sc.comp_unit = GetCompUnitForDWARFCompUnit(cu, UINT_MAX);

    sc.function = sc.comp_unit->FindFunctionByUID (func_die->GetOffset()).get();
    if (sc.function == NULL)
        sc.function = ParseCompileUnitFunction(sc, cu, func_die);

    return sc.function != NULL;
}

uint32_t
SymbolFileDWARF::ResolveSymbolContext (const Address& so_addr, uint32_t resolve_scope, SymbolContext& sc)
{
    Timer scoped_timer(__PRETTY_FUNCTION__,
                       "SymbolFileDWARF::ResolveSymbolContext (so_addr = { section = %p, offset = 0x%llx }, resolve_scope = 0x%8.8x)",
                       so_addr.GetSection(),
                       so_addr.GetOffset(),
                       resolve_scope);
    uint32_t resolved = 0;
    if (resolve_scope & (   eSymbolContextCompUnit |
                            eSymbolContextFunction |
                            eSymbolContextBlock |
                            eSymbolContextLineEntry))
    {
        lldb::addr_t file_vm_addr = so_addr.GetFileAddress();

        DWARFDebugAranges* debug_aranges = DebugAranges();
        DWARFDebugInfo* debug_info = DebugInfo();
        if (debug_aranges)
        {
            dw_offset_t cu_offset = debug_aranges->FindAddress(file_vm_addr);
            if (cu_offset != DW_INVALID_OFFSET)
            {
                uint32_t cu_idx;
                DWARFCompileUnit* cu = debug_info->GetCompileUnit(cu_offset, &cu_idx).get();
                if (cu)
                {
                    sc.comp_unit = GetCompUnitForDWARFCompUnit(cu, cu_idx);
                    assert(sc.comp_unit != NULL);
                    resolved |= eSymbolContextCompUnit;

                    if (resolve_scope & eSymbolContextLineEntry)
                    {
                        LineTable *line_table = sc.comp_unit->GetLineTable();
                        if (line_table == NULL)
                        {
                            if (ParseCompileUnitLineTable(sc))
                                line_table = sc.comp_unit->GetLineTable();
                        }
                        if (line_table != NULL)
                        {
                            if (so_addr.IsLinkedAddress())
                            {
                                Address linked_addr (so_addr);
                                linked_addr.ResolveLinkedAddress();
                                if (line_table->FindLineEntryByAddress (linked_addr, sc.line_entry))
                                {
                                    resolved |= eSymbolContextLineEntry;
                                }
                            }
                            else if (line_table->FindLineEntryByAddress (so_addr, sc.line_entry))
                            {
                                resolved |= eSymbolContextLineEntry;
                            }
                        }
                    }

                    if (resolve_scope & (eSymbolContextFunction | eSymbolContextBlock))
                    {
                        DWARFDebugInfoEntry *function_die = NULL;
                        DWARFDebugInfoEntry *block_die = NULL;
                        if (resolve_scope & eSymbolContextBlock)
                        {
                            cu->LookupAddress(file_vm_addr, &function_die, &block_die);
                        }
                        else
                        {
                            cu->LookupAddress(file_vm_addr, &function_die, NULL);
                        }

                        if (function_die != NULL)
                        {
                            sc.function = sc.comp_unit->FindFunctionByUID (function_die->GetOffset()).get();
                            if (sc.function == NULL)
                                sc.function = ParseCompileUnitFunction(sc, cu, function_die);
                        }

                        if (sc.function != NULL)
                        {
                            resolved |= eSymbolContextFunction;

                            if (resolve_scope & eSymbolContextBlock)
                            {
                                BlockList& blocks = sc.function->GetBlocks(true);

                                if (block_die != NULL)
                                    sc.block = blocks.GetBlockByID(block_die->GetOffset());
                                else
                                    sc.block = blocks.GetBlockByID(function_die->GetOffset());
                                if (sc.block)
                                    resolved |= eSymbolContextBlock;
                            }
                        }
                    }
                }
            }
        }
    }
    return resolved;
}



uint32_t
SymbolFileDWARF::ResolveSymbolContext(const FileSpec& file_spec, uint32_t line, bool check_inlines, uint32_t resolve_scope, SymbolContextList& sc_list)
{
    const uint32_t prev_size = sc_list.GetSize();
    if (resolve_scope & eSymbolContextCompUnit)
    {
        DWARFDebugInfo* debug_info = DebugInfo();
        if (debug_info)
        {
            uint32_t cu_idx;
            DWARFCompileUnit* cu = NULL;

            for (cu_idx = 0; (cu = debug_info->GetCompileUnitAtIndex(cu_idx)) != NULL; ++cu_idx)
            {
                CompileUnit *dc_cu = GetCompUnitForDWARFCompUnit(cu, cu_idx);
                bool file_spec_matches_cu_file_spec = dc_cu != NULL && FileSpec::Compare(file_spec, *dc_cu, false) == 0;
                if (check_inlines || file_spec_matches_cu_file_spec)
                {
                    SymbolContext sc (m_obj_file->GetModule());
                    sc.comp_unit = GetCompUnitForDWARFCompUnit(cu, cu_idx);
                    assert(sc.comp_unit != NULL);

                    uint32_t file_idx = UINT32_MAX;

                    // If we are looking for inline functions only and we don't
                    // find it in the support files, we are done.
                    if (check_inlines)
                    {
                        file_idx = sc.comp_unit->GetSupportFiles().FindFileIndex (1, file_spec);
                        if (file_idx == UINT32_MAX)
                            continue;
                    }

                    if (line != 0)
                    {
                        LineTable *line_table = sc.comp_unit->GetLineTable();

                        if (line_table != NULL && line != 0)
                        {
                            // We will have already looked up the file index if
                            // we are searching for inline entries.
                            if (!check_inlines)
                                file_idx = sc.comp_unit->GetSupportFiles().FindFileIndex (1, file_spec);

                            if (file_idx != UINT32_MAX)
                            {
                                uint32_t found_line;
                                uint32_t line_idx = line_table->FindLineEntryIndexByFileIndex (0, file_idx, line, false, &sc.line_entry);
                                found_line = sc.line_entry.line;

                                while (line_idx != UINT_MAX)
                                {
                                    sc.function = NULL;
                                    sc.block = NULL;
                                    if (resolve_scope & (eSymbolContextFunction | eSymbolContextBlock))
                                    {
                                        const lldb::addr_t file_vm_addr = sc.line_entry.range.GetBaseAddress().GetFileAddress();
                                        if (file_vm_addr != LLDB_INVALID_ADDRESS)
                                        {
                                            DWARFDebugInfoEntry *function_die = NULL;
                                            DWARFDebugInfoEntry *block_die = NULL;
                                            cu->LookupAddress(file_vm_addr, &function_die, resolve_scope & eSymbolContextBlock ? &block_die : NULL);

                                            if (function_die != NULL)
                                            {
                                                sc.function = sc.comp_unit->FindFunctionByUID (function_die->GetOffset()).get();
                                                if (sc.function == NULL)
                                                    sc.function = ParseCompileUnitFunction(sc, cu, function_die);
                                            }

                                            if (sc.function != NULL)
                                            {
                                                BlockList& blocks = sc.function->GetBlocks(true);

                                                if (block_die != NULL)
                                                    sc.block = blocks.GetBlockByID(block_die->GetOffset());
                                                else
                                                    sc.block = blocks.GetBlockByID(function_die->GetOffset());
                                            }
                                        }
                                    }

                                    sc_list.Append(sc);
                                    line_idx = line_table->FindLineEntryIndexByFileIndex (line_idx + 1, file_idx, found_line, true, &sc.line_entry);
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
                    else if (file_spec_matches_cu_file_spec && !check_inlines)
                    {
                        // only append the context if we aren't looking for inline call sites
                        // by file and line and if the file spec matches that of the compile unit
                        sc_list.Append(sc);
                    }

                    if (!check_inlines)
                        break;
                }
            }
        }
    }
    return sc_list.GetSize() - prev_size;
}

void
SymbolFileDWARF::Index ()
{
    if (m_indexed)
        return;
    m_indexed = true;
    Timer scoped_timer (__PRETTY_FUNCTION__,
                        "SymbolFileDWARF::Index (%s)",
                        GetObjectFile()->GetFileSpec().GetFilename().AsCString());

    DWARFDebugInfo* debug_info = DebugInfo();
    if (debug_info)
    {
        uint32_t cu_idx = 0;
        const uint32_t num_compile_units = GetNumCompileUnits();
        for (cu_idx = 0; cu_idx < num_compile_units; ++cu_idx)
        {
            DWARFCompileUnit* cu = debug_info->GetCompileUnitAtIndex(cu_idx);

            bool clear_dies = cu->ExtractDIEsIfNeeded (false) > 1;

            cu->Index (m_base_name_to_function_die,
                       m_full_name_to_function_die,
                       m_method_name_to_function_die,
                       m_selector_name_to_function_die,
                       m_name_to_global_die, 
                       m_name_to_type_die);  
            
            // Keep memory down by clearing DIEs if this generate function
            // caused them to be parsed
            if (clear_dies)
                cu->ClearDIEs (true);
        }
        
        m_base_name_to_function_die.Sort();
        m_full_name_to_function_die.Sort();
        m_method_name_to_function_die.Sort();
        m_selector_name_to_function_die.Sort();
        m_name_to_global_die.Sort(); 
        m_name_to_type_die.Sort();
    }
}

uint32_t
SymbolFileDWARF::FindGlobalVariables (const ConstString &name, bool append, uint32_t max_matches, VariableList& variables)
{
    std::vector<dw_offset_t> die_offsets;

    // If we aren't appending the results to this list, then clear the list
    if (!append)
        variables.Clear();

    // Remember how many variables are in the list before we search in case
    // we are appending the results to a variable list.
    const uint32_t original_size = variables.GetSize();

    // Index the DWARF if we haven't already
    if (!m_indexed)
        Index ();

    const UniqueCStringMap<dw_offset_t>::Entry *entry;
    
    for (entry = m_name_to_global_die.FindFirstValueForName (name.AsCString());
         entry != NULL;
         entry = m_name_to_global_die.FindNextValueForName (name.AsCString(), entry))
    {
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr (entry->value, &cu_sp);
        DWARFCompileUnit* cu = cu_sp.get();
        if (die)
        {
            SymbolContext sc;
            sc.module_sp = m_obj_file->GetModule()->GetSP();
            assert (sc.module_sp);

            sc.comp_unit = GetCompUnitForDWARFCompUnit(cu, UINT_MAX);
            assert(sc.comp_unit != NULL);

            ParseVariables(sc, cu_sp.get(), die, false, false, &variables);

            if (variables.GetSize() - original_size >= max_matches)
                break;
        }
    }

    // Return the number of variable that were appended to the list
    return variables.GetSize() - original_size;
}

uint32_t
SymbolFileDWARF::FindGlobalVariables(const RegularExpression& regex, bool append, uint32_t max_matches, VariableList& variables)
{
    std::vector<dw_offset_t> die_offsets;

    // If we aren't appending the results to this list, then clear the list
    if (!append)
        variables.Clear();

    // Remember how many variables are in the list before we search in case
    // we are appending the results to a variable list.
    const uint32_t original_size = variables.GetSize();

    // Index the DWARF if we haven't already
    if (!m_indexed)
        Index ();

    // Create the pubnames information so we can quickly lookup external symbols by name
    const size_t num_entries = m_name_to_global_die.GetSize();
    for (size_t i=0; i<num_entries; i++)
    {
        if (!regex.Execute(m_name_to_global_die.GetCStringAtIndex (i)))
            continue;

        const dw_offset_t die_offset = *m_name_to_global_die.GetValueAtIndex (i);

        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr (die_offset, &cu_sp);
        DWARFCompileUnit* cu = cu_sp.get();
        if (die)
        {
            SymbolContext sc;
            sc.module_sp = m_obj_file->GetModule()->GetSP();
            assert (sc.module_sp);


            sc.comp_unit = GetCompUnitForDWARFCompUnit(cu, UINT_MAX);
            assert(sc.comp_unit != NULL);

            ParseVariables(sc, cu_sp.get(), die, false, false, &variables);

            if (variables.GetSize() - original_size >= max_matches)
                break;
        }
    }

    // Return the number of variable that were appended to the list
    return variables.GetSize() - original_size;
}


void
SymbolFileDWARF::FindFunctions
(
    const ConstString &name, 
    UniqueCStringMap<dw_offset_t> &name_to_die,
    SymbolContextList& sc_list
)
{
    const UniqueCStringMap<dw_offset_t>::Entry *entry;
    
    SymbolContext sc;
    for (entry = name_to_die.FindFirstValueForName (name.AsCString());
         entry != NULL;
         entry = name_to_die.FindNextValueForName (name.AsCString(), entry))
    {
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr (entry->value, &cu_sp);
        if (die)
        {
            if (GetFunction (cu_sp.get(), die, sc))
            {
                // We found the function, so we should find the line table
                // and line table entry as well
                LineTable *line_table = sc.comp_unit->GetLineTable();
                if (line_table == NULL)
                {
                    if (ParseCompileUnitLineTable(sc))
                        line_table = sc.comp_unit->GetLineTable();
                }
                if (line_table != NULL)
                    line_table->FindLineEntryByAddress (sc.function->GetAddressRange().GetBaseAddress(), sc.line_entry);

                sc_list.Append(sc);
            }
        }
    }

}

uint32_t
SymbolFileDWARF::FindFunctions
(
    const ConstString &name, 
    uint32_t name_type_mask, 
    bool append, 
    SymbolContextList& sc_list
)
{
    Timer scoped_timer (__PRETTY_FUNCTION__,
                        "SymbolFileDWARF::FindFunctions (name = '%s')",
                        name.AsCString());

    std::vector<dw_offset_t> die_offsets;

    // If we aren't appending the results to this list, then clear the list
    if (!append)
        sc_list.Clear();

    // Remember how many sc_list are in the list before we search in case
    // we are appending the results to a variable list.
    uint32_t original_size = sc_list.GetSize();

    // Index the DWARF if we haven't already
    if (!m_indexed)
        Index ();

    if (name_type_mask & eFunctionNameTypeBase)
        FindFunctions (name, m_base_name_to_function_die, sc_list);

    if (name_type_mask & eFunctionNameTypeFull)
        FindFunctions (name, m_full_name_to_function_die, sc_list);

    if (name_type_mask & eFunctionNameTypeMethod)
        FindFunctions (name, m_method_name_to_function_die, sc_list);

    if (name_type_mask & eFunctionNameTypeSelector)
        FindFunctions (name, m_selector_name_to_function_die, sc_list);

    // Return the number of variable that were appended to the list
    return sc_list.GetSize() - original_size;
}


uint32_t
SymbolFileDWARF::FindFunctions(const RegularExpression& regex, bool append, SymbolContextList& sc_list)
{
    Timer scoped_timer (__PRETTY_FUNCTION__,
                        "SymbolFileDWARF::FindFunctions (regex = '%s')",
                        regex.GetText());

    std::vector<dw_offset_t> die_offsets;

    // If we aren't appending the results to this list, then clear the list
    if (!append)
        sc_list.Clear();

    // Remember how many sc_list are in the list before we search in case
    // we are appending the results to a variable list.
    uint32_t original_size = sc_list.GetSize();

    // Index the DWARF if we haven't already
    if (!m_indexed)
        Index ();

    // Create the pubnames information so we can quickly lookup external symbols by name
    // Create the pubnames information so we can quickly lookup external symbols by name
    const size_t num_entries = m_full_name_to_function_die.GetSize();
    SymbolContext sc;
    for (size_t i=0; i<num_entries; i++)
    {
        if (!regex.Execute(m_full_name_to_function_die.GetCStringAtIndex (i)))
            continue;

        const dw_offset_t die_offset = *m_full_name_to_function_die.GetValueAtIndex (i);

        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr (die_offset, &cu_sp);
        if (die)
        {
            if (GetFunction (cu_sp.get(), die, sc))
            {
                // We found the function, so we should find the line table
                // and line table entry as well
                LineTable *line_table = sc.comp_unit->GetLineTable();
                if (line_table == NULL)
                {
                    if (ParseCompileUnitLineTable(sc))
                        line_table = sc.comp_unit->GetLineTable();
                }
                if (line_table != NULL)
                    line_table->FindLineEntryByAddress (sc.function->GetAddressRange().GetBaseAddress(), sc.line_entry);


                sc_list.Append(sc);
            }
        }
    }

    // Return the number of variable that were appended to the list
    return sc_list.GetSize() - original_size;
}

#if 0
uint32_t
SymbolFileDWARF::FindTypes(const SymbolContext& sc, const ConstString &name, bool append, uint32_t max_matches, Type::Encoding encoding, lldb::user_id_t udt_uid, TypeList& types)
{
    // If we aren't appending the results to this list, then clear the list
    if (!append)
        types.Clear();

    // Create the pubnames information so we can quickly lookup external symbols by name
    DWARFDebugPubnames* pubtypes = DebugPubtypes();
    if (pubtypes)
    {
        std::vector<dw_offset_t> die_offsets;
        if (!pubtypes->Find(name.AsCString(), false, die_offsets))
        {
            DWARFDebugPubnames* pub_base_types = DebugPubBaseTypes();
            if (pub_base_types && !pub_base_types->Find(name.AsCString(), false, die_offsets))
                return 0;
        }
        return FindTypes(die_offsets, max_matches, encoding, udt_uid, types);
    }
    return 0;
}


uint32_t
SymbolFileDWARF::FindTypes(const SymbolContext& sc, const RegularExpression& regex, bool append, uint32_t max_matches, Type::Encoding encoding, lldb::user_id_t udt_uid, TypeList& types)
{
    // If we aren't appending the results to this list, then clear the list
    if (!append)
        types.Clear();

    // Create the pubnames information so we can quickly lookup external symbols by name
    DWARFDebugPubnames* pubtypes = DebugPubtypes();
    if (pubtypes)
    {
        std::vector<dw_offset_t> die_offsets;
        if (!pubtypes->Find(regex, die_offsets))
        {
            DWARFDebugPubnames* pub_base_types = DebugPubBaseTypes();
            if (pub_base_types && !pub_base_types->Find(regex, die_offsets))
                return 0;
        }

        return FindTypes(die_offsets, max_matches, encoding, udt_uid, types);
    }

    return 0;
}



uint32_t
SymbolFileDWARF::FindTypes(std::vector<dw_offset_t> die_offsets, uint32_t max_matches, Type::Encoding encoding, lldb::user_id_t udt_uid, TypeList& types)
{
    // Remember how many sc_list are in the list before we search in case
    // we are appending the results to a variable list.
    uint32_t original_size = types.Size();

    const uint32_t num_die_offsets = die_offsets.size();
    // Parse all of the types we found from the pubtypes matches
    uint32_t i;
    uint32_t num_matches = 0;
    for (i = 0; i < num_die_offsets; ++i)
    {
        dw_offset_t die_offset = die_offsets[i];
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr(die_offset, &cu_sp);

        assert(die != NULL);

        bool get_type_for_die = true;
        if (encoding)
        {
            // Check if this type has already been uniqued and registers with the module?
            Type* type = (Type*)die->GetUserData();
            if (type != NULL && type != DIE_IS_BEING_PARSED)
            {
                get_type_for_die = type->GetEncoding() == encoding;
            }
            else
            {
                dw_tag_t tag = die->Tag();
                switch (encoding)
                {
                case Type::address:
                case Type::boolean:
                case Type::complex_float:
                case Type::float_type:
                case Type::signed_int:
                case Type::signed_char:
                case Type::unsigned_int:
                case Type::unsigned_char:
                case Type::imaginary_float:
                case Type::packed_decimal:
                case Type::numeric_string:
                case Type::edited_string:
                case Type::signed_fixed:
                case Type::unsigned_fixed:
                case Type::decimal_float:
                    if (tag != DW_TAG_base_type)
                        get_type_for_die = false;
                    else
                    {
                        if (die->GetAttributeValueAsUnsigned(this, cu_sp.get(), DW_AT_encoding, Type::invalid) != encoding)
                            get_type_for_die = false;
                    }
                    break;

                case Type::indirect_const:      get_type_for_die = tag == DW_TAG_const_type; break;
                case Type::indirect_restrict:       get_type_for_die = tag == DW_TAG_restrict_type; break;
                case Type::indirect_volatile:       get_type_for_die = tag == DW_TAG_volatile_type; break;
                case Type::indirect_typedef:        get_type_for_die = tag == DW_TAG_typedef; break;
                case Type::indirect_pointer:        get_type_for_die = tag == DW_TAG_pointer_type; break;
                case Type::indirect_reference:  get_type_for_die = tag == DW_TAG_reference_type; break;

                case Type::user_defined_type:
                    switch (tag)
                    {
                    case DW_TAG_array_type:
                        get_type_for_die = UserDefTypeArray::OwnsUserDefTypeUID(udt_uid);
                        break;

                    case DW_TAG_structure_type:
                    case DW_TAG_union_type:
                    case DW_TAG_class_type:
                        get_type_for_die = UserDefTypeStruct::OwnsUserDefTypeUID(udt_uid);
                        break;

                    case DW_TAG_enumeration_type:
                        get_type_for_die = UserDefTypeEnum::OwnsUserDefTypeUID(udt_uid);
                        break;

                    case DW_TAG_subprogram:
                    case DW_TAG_subroutine_type:
                        get_type_for_die = UserDefTypeFunction::OwnsUserDefTypeUID(udt_uid);
                        break;
                    }
                }
            }
        }

        if (get_type_for_die)
        {
            TypeSP owning_type_sp;
            TypeSP type_sp(GetTypeForDIE(cu_sp.get(), die, owning_type_sp, NULL, 0, 0));

            if (type_sp.get())
            {
                // See if we are filtering results based on encoding?
                bool add_type = (encoding == Type::invalid);
                if (!add_type)
                {
                    // We are filtering base on encoding, so lets check the resulting type encoding
                    add_type = (encoding == type_sp->GetEncoding());
                    if (add_type)
                    {
                        // The type encoding matches, if this is a user defined type, lets
                        // make sure the exact user define type uid matches if one was provided
                        if (encoding == Type::user_defined_type && udt_uid != LLDB_INVALID_UID)
                        {
                            UserDefType* udt = type_sp->GetUserDefinedType().get();
                            if (udt)
                                add_type = udt->UserDefinedTypeUID() == udt_uid;
                        }
                    }
                }
                // Add the type to our list as long as everything matched
                if (add_type)
                {
                    types.InsertUnique(type_sp);
                    if (++num_matches >= max_matches)
                        break;
                }
            }
        }
    }

    // Return the number of variable that were appended to the list
    return types.Size() - original_size;
}

#endif


size_t
SymbolFileDWARF::ParseChildParameters
(
    const SymbolContext& sc,
    TypeSP& type_sp,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *parent_die,
    TypeList* type_list,
    std::vector<void *>& function_param_types,
    std::vector<clang::ParmVarDecl*>& function_param_decls
)
{
    if (parent_die == NULL)
        return 0;

    size_t count = 0;
    const DWARFDebugInfoEntry *die;
    for (die = parent_die->GetFirstChild(); die != NULL; die = die->GetSibling())
    {
        dw_tag_t tag = die->Tag();
        switch (tag)
        {
        case DW_TAG_formal_parameter:
            {
                DWARFDebugInfoEntry::Attributes attributes;
                const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                if (num_attributes > 0)
                {
                    const char *name = NULL;
                    Declaration decl;
                    dw_offset_t param_type_die_offset = DW_INVALID_OFFSET;
                    // one of None, Auto, Register, Extern, Static, PrivateExtern

                    clang::VarDecl::StorageClass storage = clang::VarDecl::None;
                    uint32_t i;
                    for (i=0; i<num_attributes; ++i)
                    {
                        const dw_attr_t attr = attributes.AttributeAtIndex(i);
                        DWARFFormValue form_value;
                        if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                        {
                            switch (attr)
                            {
                            case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                            case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                            case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                            case DW_AT_name:        name = form_value.AsCString(&get_debug_str_data()); break;
                            case DW_AT_type:        param_type_die_offset = form_value.Reference(dwarf_cu); break;
                            case DW_AT_location:
    //                          if (form_value.BlockData())
    //                          {
    //                              const DataExtractor& debug_info_data = debug_info();
    //                              uint32_t block_length = form_value.Unsigned();
    //                              DataExtractor location(debug_info_data, form_value.BlockData() - debug_info_data.GetDataStart(), block_length);
    //                          }
    //                          else
    //                          {
    //                          }
    //                          break;
                            case DW_AT_artificial:
                            case DW_AT_const_value:
                            case DW_AT_default_value:
                            case DW_AT_description:
                            case DW_AT_endianity:
                            case DW_AT_is_optional:
                            case DW_AT_segment:
                            case DW_AT_variable_parameter:
                            default:
                            case DW_AT_abstract_origin:
                            case DW_AT_sibling:
                                break;
                            }
                        }
                    }
                    Type *dc_type = ResolveTypeUID(param_type_die_offset);
                    if (dc_type)
                    {
                        function_param_types.push_back (dc_type->GetOpaqueClangQualType());

                        clang::ParmVarDecl *param_var_decl = type_list->GetClangASTContext().CreateParmeterDeclaration (name, dc_type->GetOpaqueClangQualType(), storage);
                        assert(param_var_decl);
                        function_param_decls.push_back(param_var_decl);
                    }
                }
            }
            break;

        default:
            break;
        }
    }
    return count;
}

size_t
SymbolFileDWARF::ParseChildEnumerators
(
    const SymbolContext& sc,
    TypeSP& type_sp,
    void * enumerator_qual_type,
    uint32_t enumerator_byte_size,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *parent_die
)
{
    if (parent_die == NULL)
        return 0;

    size_t enumerators_added = 0;
    const DWARFDebugInfoEntry *die;
    for (die = parent_die->GetFirstChild(); die != NULL; die = die->GetSibling())
    {
        const dw_tag_t tag = die->Tag();
        if (tag == DW_TAG_enumerator)
        {
            DWARFDebugInfoEntry::Attributes attributes;
            const size_t num_child_attributes = die->GetAttributes(this, dwarf_cu, attributes);
            if (num_child_attributes > 0)
            {
                const char *name = NULL;
                bool got_value = false;
                int64_t enum_value = 0;
                Declaration decl;

                uint32_t i;
                for (i=0; i<num_child_attributes; ++i)
                {
                    const dw_attr_t attr = attributes.AttributeAtIndex(i);
                    DWARFFormValue form_value;
                    if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                    {
                        switch (attr)
                        {
                        case DW_AT_const_value:
                            got_value = true;
                            enum_value = form_value.Unsigned();
                            break;

                        case DW_AT_name:
                            name = form_value.AsCString(&get_debug_str_data());
                            break;

                        case DW_AT_description:
                        default:
                        case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                        case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                        case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                        case DW_AT_sibling:
                            break;
                        }
                    }
                }

                if (name && name[0] && got_value)
                {
                    TypeList* type_list = m_obj_file->GetModule()->GetTypeList();
                    type_list->GetClangASTContext().AddEnumerationValueToEnumerationType (type_sp->GetOpaqueClangQualType(), enumerator_qual_type, decl, name, enum_value, enumerator_byte_size * 8);
                    ++enumerators_added;
                }
            }
        }
    }
    return enumerators_added;
}

void
SymbolFileDWARF::ParseChildArrayInfo
(
    const SymbolContext& sc,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *parent_die,
    int64_t& first_index,
    std::vector<uint64_t>& element_orders,
    uint32_t& byte_stride,
    uint32_t& bit_stride
)
{
    if (parent_die == NULL)
        return;

    const DWARFDebugInfoEntry *die;
    for (die = parent_die->GetFirstChild(); die != NULL; die = die->GetSibling())
    {
        const dw_tag_t tag = die->Tag();
        switch (tag)
        {
        case DW_TAG_enumerator:
            {
                DWARFDebugInfoEntry::Attributes attributes;
                const size_t num_child_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                if (num_child_attributes > 0)
                {
                    const char *name = NULL;
                    bool got_value = false;
                    int64_t enum_value = 0;

                    uint32_t i;
                    for (i=0; i<num_child_attributes; ++i)
                    {
                        const dw_attr_t attr = attributes.AttributeAtIndex(i);
                        DWARFFormValue form_value;
                        if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                        {
                            switch (attr)
                            {
                            case DW_AT_const_value:
                                got_value = true;
                                enum_value = form_value.Unsigned();
                                break;

                            case DW_AT_name:
                                name = form_value.AsCString(&get_debug_str_data());
                                break;

                            case DW_AT_description:
                            default:
                            case DW_AT_decl_file:
                            case DW_AT_decl_line:
                            case DW_AT_decl_column:
                            case DW_AT_sibling:
                                break;
                            }
                        }
                    }
                }
            }
            break;

        case DW_TAG_subrange_type:
            {
                DWARFDebugInfoEntry::Attributes attributes;
                const size_t num_child_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                if (num_child_attributes > 0)
                {
                    const char *name = NULL;
                    bool got_value = false;
                    uint64_t byte_size = 0;
                    int64_t enum_value = 0;
                    uint64_t num_elements = 0;
                    uint64_t lower_bound = 0;
                    uint64_t upper_bound = 0;
                    uint32_t i;
                    for (i=0; i<num_child_attributes; ++i)
                    {
                        const dw_attr_t attr = attributes.AttributeAtIndex(i);
                        DWARFFormValue form_value;
                        if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                        {
                            switch (attr)
                            {
                            case DW_AT_const_value:
                                got_value = true;
                                enum_value = form_value.Unsigned();
                                break;

                            case DW_AT_name:
                                name = form_value.AsCString(&get_debug_str_data());
                                break;

                            case DW_AT_count:
                                num_elements = form_value.Unsigned();
                                break;

                            case DW_AT_bit_stride:
                                bit_stride = form_value.Unsigned();
                                break;

                            case DW_AT_byte_stride:
                                byte_stride = form_value.Unsigned();
                                break;

                            case DW_AT_byte_size:
                                byte_size = form_value.Unsigned();
                                break;

                            case DW_AT_lower_bound:
                                lower_bound = form_value.Unsigned();
                                break;

                            case DW_AT_upper_bound:
                                upper_bound = form_value.Unsigned();
                                break;

                            default:
                                //printf("0x%8.8x: %-30s skipping attribute at 0x%8.8x: %s\n", die->GetOffset(), DW_TAG_value_to_name(tag), attributes.die_offsets[i], DW_AT_value_to_name(attr));  // remove this, debug only

                            case DW_AT_abstract_origin:
                            case DW_AT_accessibility:
                            case DW_AT_allocated:
                            case DW_AT_associated:
                            case DW_AT_data_location:
                            case DW_AT_declaration:
                            case DW_AT_description:
                            case DW_AT_sibling:
                            case DW_AT_threads_scaled:
                            case DW_AT_type:
                            case DW_AT_visibility:
                                break;
                            }
                        }
                    }

                    if (upper_bound > lower_bound)
                        num_elements = upper_bound - lower_bound + 1;

                    if (num_elements > 0)
                        element_orders.push_back (num_elements);
                }
            }
            break;
        }
    }
}

Type*
SymbolFileDWARF::GetUniquedTypeForDIEOffset(dw_offset_t type_die_offset, TypeSP& owning_type_sp, int32_t child_type, uint32_t idx, bool safe)
{
    if (type_die_offset != DW_INVALID_OFFSET)
    {
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* type_die = DebugInfo()->GetDIEPtr(type_die_offset, &cu_sp);
        assert(type_die != NULL);
        GetTypeForDIE(cu_sp.get(), type_die, owning_type_sp, child_type, idx);
        // Return the uniqued type if there is one
        Type* type = (Type*)type_die->GetUserData();
        if (type == DIE_IS_BEING_PARSED && safe)
            return NULL;
        return type;
    }
    return NULL;
}

TypeSP
SymbolFileDWARF::GetTypeForDIE(DWARFCompileUnit *cu, const DWARFDebugInfoEntry* die, TypeSP& owning_type_sp, int32_t child_type, uint32_t idx)
{
    TypeSP type_sp;
    if (die != NULL)
    {
        assert(cu != NULL);
        Type *type_ptr = (Type *)die->GetUserData();
        if (type_ptr == NULL)
        {
            SymbolContext sc(GetCompUnitForDWARFCompUnit(cu));
            bool type_is_new = false;
            type_sp = ParseType(sc, cu, die, type_is_new);
            type_ptr = (Type *)die->GetUserData();
            if (owning_type_sp.get() == NULL)
                owning_type_sp = type_sp;
        }
        else if (type_ptr != DIE_IS_BEING_PARSED)
        {
            // Grab the existing type from the master types lists
            type_sp = m_obj_file->GetModule()->GetTypeList()->FindType(type_ptr->GetID());
        }

    }
    return type_sp;
}

clang::DeclContext *
SymbolFileDWARF::GetClangDeclContextForDIEOffset (dw_offset_t die_offset)
{
    if (die_offset != DW_INVALID_OFFSET)
    {
        DWARFCompileUnitSP cu_sp;
        const DWARFDebugInfoEntry* die = DebugInfo()->GetDIEPtr(die_offset, &cu_sp);
        return GetClangDeclContextForDIE (cu_sp.get(), die);
    }
    return NULL;
}



clang::DeclContext *
SymbolFileDWARF::GetClangDeclContextForDIE (const DWARFCompileUnit *cu, const DWARFDebugInfoEntry *die)
{
    DIEToDeclContextMap::iterator pos = m_die_to_decl_ctx.find(die);
    if (pos != m_die_to_decl_ctx.end())
        return pos->second;

    while (die != NULL)
    {
        switch (die->Tag())
        {
        case DW_TAG_namespace:
            {
                const char *namespace_name = die->GetAttributeValueAsString(this, cu, DW_AT_name, NULL);
                if (namespace_name)
                {
                    TypeList* type_list = m_obj_file->GetModule()->GetTypeList();
                    assert(type_list);
                    Declaration decl;   // TODO: fill in the decl object
                    clang::NamespaceDecl *namespace_decl = type_list->GetClangASTContext().GetUniqueNamespaceDeclaration (namespace_name, decl, GetClangDeclContextForDIE (cu, die->GetParent()));
                    if (namespace_decl)
                        m_die_to_decl_ctx[die] = (clang::DeclContext*)namespace_decl;
                    return namespace_decl;
                }
            }
            break;

        default:
            break;
        }
        clang::DeclContext *decl_ctx;
        decl_ctx = GetClangDeclContextForDIEOffset (die->GetAttributeValueAsUnsigned(this, cu, DW_AT_specification, DW_INVALID_OFFSET));
        if (decl_ctx)
            return decl_ctx;

        decl_ctx = GetClangDeclContextForDIEOffset (die->GetAttributeValueAsUnsigned(this, cu, DW_AT_abstract_origin, DW_INVALID_OFFSET));
        if (decl_ctx)
            return decl_ctx;

        die = die->GetParent();
    }
    return NULL;
}

TypeSP
SymbolFileDWARF::ParseType(const SymbolContext& sc, const DWARFCompileUnit* dwarf_cu, const DWARFDebugInfoEntry *die, bool &type_is_new)
{
    TypeSP type_sp;

    uint32_t accessibility = clang::AS_none;
    if (die != NULL)
    {
        dw_tag_t tag = die->Tag();
        if (die->GetUserData() == NULL)
        {
            type_is_new = true;

            bool is_forward_declaration = false;
            DWARFDebugInfoEntry::Attributes attributes;
            const char *type_name_cstr = NULL;
            ConstString type_name_dbstr;
            Type::EncodingUIDType encoding_uid_type = Type::eIsTypeWithUID;
            void *clang_type = NULL;

            TypeList* type_list = m_obj_file->GetModule()->GetTypeList();
            dw_attr_t attr;

            switch (tag)
            {
            case DW_TAG_base_type:
            case DW_TAG_pointer_type:
            case DW_TAG_reference_type:
            case DW_TAG_typedef:
            case DW_TAG_const_type:
            case DW_TAG_restrict_type:
            case DW_TAG_volatile_type:
                {
                    //printf("0x%8.8x: %s (ParesTypes)\n", die->GetOffset(), DW_TAG_value_to_name(tag));
                    // Set a bit that lets us know that we are currently parsing this
                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(DIE_IS_BEING_PARSED);

                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                    Declaration decl;
                    uint32_t encoding = 0;
                    size_t byte_size = 0;
                    lldb::user_id_t encoding_uid = LLDB_INVALID_UID;

                    if (num_attributes > 0)
                    {
                        uint32_t i;
                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                                case DW_AT_name:
                                    type_name_cstr = form_value.AsCString(&get_debug_str_data());
                                    type_name_dbstr.SetCString(type_name_cstr);
                                    break;
                                case DW_AT_byte_size:   byte_size = form_value.Unsigned();  break;
                                case DW_AT_encoding:    encoding = form_value.Unsigned(); break;
                                case DW_AT_type:        encoding_uid = form_value.Reference(dwarf_cu); break;
                                default:
                                case DW_AT_sibling:
                                    break;
                                }
                            }
                        }
                    }

                    switch (tag)
                    {
                    default:
                    case DW_TAG_base_type:
                        clang_type = type_list->GetClangASTContext().GetBuiltinTypeForDWARFEncodingAndBitSize (type_name_cstr, encoding, byte_size * 8);
                        break;

                    case DW_TAG_pointer_type:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::ePointerToTypeWithUID;
                        break;

                    case DW_TAG_reference_type:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::eLValueReferenceToTypeWithUID;
                        break;

                    case DW_TAG_typedef:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::eTypedefToTypeWithUID;
                        break;

                    case DW_TAG_const_type:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::eIsConstTypeWithUID; //ClangASTContext::AddConstModifier (clang_type);
                        break;

                    case DW_TAG_restrict_type:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::eIsRestrictTypeWithUID; //ClangASTContext::AddRestrictModifier (clang_type);
                        break;

                    case DW_TAG_volatile_type:
                        // The encoding_uid will be embedded into the
                        // Type object and will be looked up when the Type::GetOpaqueClangQualType()
                        encoding_uid_type = Type::eIsVolatileTypeWithUID; //ClangASTContext::AddVolatileModifier (clang_type);
                        break;
                    }

                    type_sp.reset( new Type(die->GetOffset(), this, type_name_dbstr, byte_size, NULL, encoding_uid, encoding_uid_type, &decl, clang_type));

                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());


//                  Type* encoding_type = GetUniquedTypeForDIEOffset(encoding_uid, type_sp, NULL, 0, 0, false);
//                  if (encoding_type != NULL)
//                  {
//                      if (encoding_type != DIE_IS_BEING_PARSED)
//                          type_sp->SetEncodingType(encoding_type);
//                      else
//                          m_indirect_fixups.push_back(type_sp.get());
//                  }
                }
                break;

            case DW_TAG_structure_type:
            case DW_TAG_union_type:
            case DW_TAG_class_type:
                {
                    //printf("0x%8.8x: %s (ParesTypes)\n", die->GetOffset(), DW_TAG_value_to_name(tag));
                    // Set a bit that lets us know that we are currently parsing this
                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(DIE_IS_BEING_PARSED);

                    size_t byte_size = 0;
                    //bool struct_is_class = false;
                    Declaration decl;
                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                    if (num_attributes > 0)
                    {
                        uint32_t i;
                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                                case DW_AT_name:
                                    type_name_cstr = form_value.AsCString(&get_debug_str_data());
                                    type_name_dbstr.SetCString(type_name_cstr);
                                    break;
                                case DW_AT_byte_size:   byte_size = form_value.Unsigned(); break;
                                case DW_AT_accessibility: accessibility = DwarfToClangAccessibility(form_value.Unsigned()); break; break;
                                case DW_AT_declaration: is_forward_declaration = form_value.Unsigned() != 0; break;
                                case DW_AT_allocated:
                                case DW_AT_associated:
                                case DW_AT_data_location:
                                case DW_AT_description:
                                case DW_AT_start_scope:
                                case DW_AT_visibility:
                                default:
                                case DW_AT_sibling:
                                    break;
                                }
                            }
                        }
                    }

                    int tag_decl_kind = -1;
                    int default_accessibility = clang::AS_none;
                    if (tag == DW_TAG_structure_type)
                    {
                        tag_decl_kind = clang::TTK_Struct;
                        default_accessibility = clang::AS_public;
                    }
                    else if (tag == DW_TAG_union_type)
                    {
                        tag_decl_kind = clang::TTK_Union;
                        default_accessibility = clang::AS_public;
                    }
                    else if (tag == DW_TAG_class_type)
                    {
                        tag_decl_kind = clang::TTK_Class;
                        default_accessibility = clang::AS_private;
                    }

                    assert (tag_decl_kind != -1);
                    clang_type = type_list->GetClangASTContext().CreateRecordType (type_name_cstr, tag_decl_kind, GetClangDeclContextForDIE (dwarf_cu, die));

                    m_die_to_decl_ctx[die] = ClangASTContext::GetDeclContextForType (clang_type);
                    type_sp.reset( new Type(die->GetOffset(), this, type_name_dbstr, byte_size, NULL, LLDB_INVALID_UID, Type::eIsTypeWithUID, &decl, clang_type));

                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());

//                  assert(type_sp.get());
//                  if (accessibility)
//                      type_sp->SetAccess(accessibility);
//
                    type_list->GetClangASTContext().StartTagDeclarationDefinition (clang_type);
                    if (die->HasChildren())
                    {
                        std::vector<clang::CXXBaseSpecifier *> base_classes;
                        std::vector<int> member_accessibilities;
                        bool is_a_class = false;
                        ParseChildMembers(sc, type_sp, dwarf_cu, die, base_classes, member_accessibilities, default_accessibility, is_a_class);
                        // If we have a DW_TAG_structure_type instead of a DW_TAG_class_type we
                        // need to tell the clang type it is actually a class.
                        if (is_a_class && tag_decl_kind != clang::TTK_Class)
                            type_list->GetClangASTContext().SetTagTypeKind (clang_type, clang::TTK_Class);

                        // Since DW_TAG_structure_type gets used for both classes
                        // and structures, we may need to set any DW_TAG_member
                        // fields to have a "private" access if none was specified.
                        // When we parsed the child members we tracked that actual
                        // accessibility value for each DW_TAG_member in the
                        // "member_accessibilities" array. If the value for the
                        // member is zero, then it was set to the "default_accessibility"
                        // which for structs was "public". Below we correct this
                        // by setting any fields to "private" that weren't correctly
                        // set.
                        if (is_a_class && !member_accessibilities.empty())
                        {
                            // This is a class and all members that didn't have
                            // their access specified are private.
                            type_list->GetClangASTContext().SetDefaultAccessForRecordFields (clang_type, clang::AS_private, member_accessibilities.data(), member_accessibilities.size());
                        }

                        if (!base_classes.empty())
                        {
                            type_list->GetClangASTContext().SetBaseClassesForClassType (clang_type, base_classes.data(), base_classes.size());
                        }
                        
                        // Clang will copy each CXXBaseSpecifier in "base_classes"
                        // so we have to free them all.
                        ClangASTContext::DeleteBaseClassSpecifiers (base_classes.data(), base_classes.size());
                    }
                    type_list->GetClangASTContext().CompleteTagDeclarationDefinition (clang_type);
                }
                break;

            case DW_TAG_enumeration_type:
                {
                    //printf("0x%8.8x: %s (ParesTypes)\n", die->GetOffset(), DW_TAG_value_to_name(tag));
                    // Set a bit that lets us know that we are currently parsing this
                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(DIE_IS_BEING_PARSED);

                    size_t byte_size = 0;
                    lldb::user_id_t encoding_uid = DW_INVALID_OFFSET;
                    Declaration decl;

                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                    if (num_attributes > 0)
                    {
                        uint32_t i;

                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                                case DW_AT_name:
                                    type_name_cstr = form_value.AsCString(&get_debug_str_data());
                                    type_name_dbstr.SetCString(type_name_cstr);
                                    break;
                                case DW_AT_type:        encoding_uid = form_value.Reference(dwarf_cu); break;
                                case DW_AT_byte_size:   byte_size = form_value.Unsigned(); break;
                                case DW_AT_accessibility: accessibility = DwarfToClangAccessibility(form_value.Unsigned()); break;
                                case DW_AT_declaration: is_forward_declaration = form_value.Unsigned() != 0; break;
                                case DW_AT_allocated:
                                case DW_AT_associated:
                                case DW_AT_bit_stride:
                                case DW_AT_byte_stride:
                                case DW_AT_data_location:
                                case DW_AT_description:
                                case DW_AT_start_scope:
                                case DW_AT_visibility:
                                case DW_AT_specification:
                                case DW_AT_abstract_origin:
                                case DW_AT_sibling:
                                    break;
                                }
                            }
                        }

                        clang_type = type_list->GetClangASTContext().CreateEnumerationType(decl, type_name_cstr);
                        m_die_to_decl_ctx[die] = ClangASTContext::GetDeclContextForType (clang_type);
                        type_sp.reset( new Type(die->GetOffset(), this, type_name_dbstr, byte_size, NULL, encoding_uid, Type::eIsTypeWithUID, &decl, clang_type));

                        const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());

                        if (die->HasChildren())
                        {
                            type_list->GetClangASTContext().StartTagDeclarationDefinition (clang_type);
                            void *enumerator_qual_type = type_list->GetClangASTContext().GetBuiltinTypeForDWARFEncodingAndBitSize (NULL, DW_ATE_signed, byte_size * 8);
                            ParseChildEnumerators(sc, type_sp, enumerator_qual_type, byte_size, dwarf_cu, die);
                            type_list->GetClangASTContext().CompleteTagDeclarationDefinition (clang_type);
                        }
                    }
                }
                break;

            case DW_TAG_subprogram:
            case DW_TAG_subroutine_type:
                {
                    //printf("0x%8.8x: %s (ParesTypes)\n", die->GetOffset(), DW_TAG_value_to_name(tag));
                    // Set a bit that lets us know that we are currently parsing this
                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(DIE_IS_BEING_PARSED);

                    const char *mangled = NULL;
                    dw_offset_t type_die_offset = DW_INVALID_OFFSET;
                    Declaration decl;
                    bool isVariadic = false;
                    bool is_inline = false;
                    unsigned type_quals = 0;
                    clang::FunctionDecl::StorageClass storage = clang::FunctionDecl::None;//, Extern, Static, PrivateExtern


                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                    if (num_attributes > 0)
                    {
                        uint32_t i;
                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                                case DW_AT_name:
                                    type_name_cstr = form_value.AsCString(&get_debug_str_data());
                                    type_name_dbstr.SetCString(type_name_cstr);
                                    break;

                                case DW_AT_MIPS_linkage_name:   mangled = form_value.AsCString(&get_debug_str_data()); break;
                                case DW_AT_type:                type_die_offset = form_value.Reference(dwarf_cu); break;
                                case DW_AT_accessibility:       accessibility = DwarfToClangAccessibility(form_value.Unsigned()); break;
                                case DW_AT_declaration:         is_forward_declaration = form_value.Unsigned() != 0; break;
                                case DW_AT_external:
                                    if (form_value.Unsigned())
                                    {
                                        if (storage == clang::FunctionDecl::None)
                                            storage = clang::FunctionDecl::Extern;
                                        else
                                            storage = clang::FunctionDecl::PrivateExtern;
                                    }
                                    break;
                                case DW_AT_inline:
                                    is_inline = form_value.Unsigned() != 0;
                                    break;

                                case DW_AT_allocated:
                                case DW_AT_associated:
                                case DW_AT_address_class:
                                case DW_AT_artificial:
                                case DW_AT_calling_convention:
                                case DW_AT_data_location:
                                case DW_AT_elemental:
                                case DW_AT_entry_pc:
                                case DW_AT_explicit:
                                case DW_AT_frame_base:
                                case DW_AT_high_pc:
                                case DW_AT_low_pc:
                                case DW_AT_object_pointer:
                                case DW_AT_prototyped:
                                case DW_AT_pure:
                                case DW_AT_ranges:
                                case DW_AT_recursive:
                                case DW_AT_return_addr:
                                case DW_AT_segment:
                                case DW_AT_specification:
                                case DW_AT_start_scope:
                                case DW_AT_static_link:
                                case DW_AT_trampoline:
                                case DW_AT_visibility:
                                case DW_AT_virtuality:
                                case DW_AT_vtable_elem_location:
                                case DW_AT_abstract_origin:
                                case DW_AT_description:
                                case DW_AT_sibling:
                                    break;
                                }
                            }
                        }

                        void *return_clang_type = NULL;
                        Type *func_type = ResolveTypeUID(type_die_offset);
                        if (func_type)
                            return_clang_type = func_type->GetOpaqueClangQualType();
                        else
                            return_clang_type = type_list->GetClangASTContext().GetVoidBuiltInType();

                        std::vector<void *> function_param_types;
                        std::vector<clang::ParmVarDecl*> function_param_decls;

                        // Parse the function children for the parameters
                        ParseChildParameters(sc, type_sp, dwarf_cu, die, type_list, function_param_types, function_param_decls);

                        clang_type = type_list->GetClangASTContext().CreateFunctionType (return_clang_type, &function_param_types[0], function_param_types.size(), isVariadic, type_quals);
                        if (type_name_cstr)
                        {
                            clang::FunctionDecl *function_decl = type_list->GetClangASTContext().CreateFunctionDeclaration (type_name_cstr, clang_type, storage, is_inline);
                            // Add the decl to our DIE to decl context map
                            assert (function_decl);
                            m_die_to_decl_ctx[die] = function_decl;
                            if (!function_param_decls.empty())
                                type_list->GetClangASTContext().SetFunctionParameters (function_decl, function_param_decls.data(), function_param_decls.size());
                        }
                        type_sp.reset( new Type(die->GetOffset(), this, type_name_dbstr, 0, NULL, LLDB_INVALID_UID, Type::eIsTypeWithUID, &decl, clang_type));

                        const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());
                        assert(type_sp.get());
                    }
                }
                break;

            case DW_TAG_array_type:
                {
                    //printf("0x%8.8x: %s (ParesTypes)\n", die->GetOffset(), DW_TAG_value_to_name(tag));
                    // Set a bit that lets us know that we are currently parsing this
                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(DIE_IS_BEING_PARSED);

                    size_t byte_size = 0;
                    lldb::user_id_t type_die_offset = DW_INVALID_OFFSET;
                    Declaration decl;
                    int64_t first_index = 0;
                    uint32_t byte_stride = 0;
                    uint32_t bit_stride = 0;
                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);

                    if (num_attributes > 0)
                    {
                        uint32_t i;
                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                                case DW_AT_name:
                                    type_name_cstr = form_value.AsCString(&get_debug_str_data());
                                    type_name_dbstr.SetCString(type_name_cstr);
                                    break;

                                case DW_AT_type:            type_die_offset = form_value.Reference(dwarf_cu); break;
                                case DW_AT_byte_size:       byte_size = form_value.Unsigned(); break;
                                case DW_AT_byte_stride:     byte_stride = form_value.Unsigned(); break;
                                case DW_AT_bit_stride:      bit_stride = form_value.Unsigned(); break;
                                case DW_AT_accessibility:   accessibility = DwarfToClangAccessibility(form_value.Unsigned()); break;
                                case DW_AT_declaration:     is_forward_declaration = form_value.Unsigned() != 0; break;
                                case DW_AT_allocated:
                                case DW_AT_associated:
                                case DW_AT_data_location:
                                case DW_AT_description:
                                case DW_AT_ordering:
                                case DW_AT_start_scope:
                                case DW_AT_visibility:
                                case DW_AT_specification:
                                case DW_AT_abstract_origin:
                                case DW_AT_sibling:
                                    break;
                                }
                            }
                        }

                        Type *element_type = ResolveTypeUID(type_die_offset);

                        if (element_type)
                        {
                            std::vector<uint64_t> element_orders;
                            ParseChildArrayInfo(sc, dwarf_cu, die, first_index, element_orders, byte_stride, bit_stride);
                            if (byte_stride == 0 && bit_stride == 0)
                                byte_stride = element_type->GetByteSize();
                            void *array_element_type = element_type->GetOpaqueClangQualType();
                            uint64_t array_element_bit_stride = byte_stride * 8 + bit_stride;
                            uint64_t num_elements = 0;
                            std::vector<uint64_t>::const_reverse_iterator pos;
                            std::vector<uint64_t>::const_reverse_iterator end = element_orders.rend();
                            for (pos = element_orders.rbegin(); pos != end; ++pos)
                            {
                                num_elements = *pos;
                                clang_type = type_list->GetClangASTContext().CreateArrayType (array_element_type, num_elements, num_elements * array_element_bit_stride);
                                array_element_type = clang_type;
                                array_element_bit_stride = array_element_bit_stride * num_elements;
                            }
                            ConstString empty_name;
                            type_sp.reset( new Type(die->GetOffset(), this, empty_name, array_element_bit_stride / 8, NULL, LLDB_INVALID_UID, Type::eIsTypeWithUID, &decl, clang_type));
                            const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());
                        }
                    }
                }
                break;

            case DW_TAG_ptr_to_member_type:
                {
                    dw_offset_t type_die_offset = DW_INVALID_OFFSET;
                    dw_offset_t containing_type_die_offset = DW_INVALID_OFFSET;

                    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
                    
                    if (num_attributes > 0) {
                        uint32_t i;
                        for (i=0; i<num_attributes; ++i)
                        {
                            attr = attributes.AttributeAtIndex(i);
                            DWARFFormValue form_value;
                            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
                            {
                                switch (attr)
                                {
                                    case DW_AT_type:
                                        type_die_offset = form_value.Reference(dwarf_cu); break;
                                    case DW_AT_containing_type:
                                        containing_type_die_offset = form_value.Reference(dwarf_cu); break;
                                }
                            }
                        }
                        
                        Type *pointee_type = ResolveTypeUID(type_die_offset);
                        Type *class_type = ResolveTypeUID(containing_type_die_offset);
                        
                        void *pointee_clang_type = pointee_type->GetOpaqueClangQualType();
                        void *class_clang_type = class_type->GetOpaqueClangQualType();

                        void *clang_type = type_list->GetClangASTContext().CreateMemberPointerType(pointee_clang_type, class_clang_type);

                        size_t byte_size = ClangASTContext::GetTypeBitSize(type_list->GetClangASTContext().getASTContext(), clang_type) / 8;

                        type_sp.reset( new Type(die->GetOffset(), this, type_name_dbstr, byte_size, NULL, LLDB_INVALID_UID, Type::eIsTypeWithUID, NULL, clang_type));
                        const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(type_sp.get());
                    }
                                            
                    break;
                }
            default:
                assert(false && "Unhandled type tag!");
                break;
            }

            if (type_sp.get())
            {
                const DWARFDebugInfoEntry *sc_parent_die = GetParentSymbolContextDIE(die);
                dw_tag_t sc_parent_tag = sc_parent_die ? sc_parent_die->Tag() : 0;

                SymbolContextScope * symbol_context_scope = NULL;
                if (sc_parent_tag == DW_TAG_compile_unit)
                {
                    symbol_context_scope = sc.comp_unit;
                }
                else if (sc.function != NULL)
                {
                    symbol_context_scope = sc.function->GetBlocks(true).GetBlockByID(sc_parent_die->GetOffset());
                    if (symbol_context_scope == NULL)
                        symbol_context_scope = sc.function;
                }

                if (symbol_context_scope != NULL)
                {
                    type_sp->SetSymbolContextScope(symbol_context_scope);
                }

//              if (udt_sp.get())
//              {
//                  if (is_forward_declaration)
//                      udt_sp->GetFlags().Set(UserDefType::flagIsForwardDefinition);
//                  type_sp->SetUserDefinedType(udt_sp);
//              }

                if (type_sp.unique())
                {
                    // We are ready to put this type into the uniqued list up at the module level
                    TypeSP uniqued_type_sp(m_obj_file->GetModule()->GetTypeList()->InsertUnique(type_sp));

                    const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(uniqued_type_sp.get());

                    type_sp = uniqued_type_sp;
                }
            }
        }
        else
        {
            switch (tag)
            {
            case DW_TAG_base_type:
            case DW_TAG_pointer_type:
            case DW_TAG_reference_type:
            case DW_TAG_typedef:
            case DW_TAG_const_type:
            case DW_TAG_restrict_type:
            case DW_TAG_volatile_type:
            case DW_TAG_structure_type:
            case DW_TAG_union_type:
            case DW_TAG_class_type:
            case DW_TAG_enumeration_type:
            case DW_TAG_subprogram:
            case DW_TAG_subroutine_type:
            case DW_TAG_array_type:
                {
                    Type *existing_type = (Type*)die->GetUserData();
                    if (existing_type != DIE_IS_BEING_PARSED)
                    {
                        type_sp = m_obj_file->GetModule()->GetTypeList()->FindType(existing_type->GetID());
                    }
                }
                break;
            default:
                //assert(!"invalid type tag...");
                break;
            }
        }
    }
    return type_sp;
}

size_t
SymbolFileDWARF::ParseTypes (const SymbolContext& sc, const DWARFCompileUnit* dwarf_cu, const DWARFDebugInfoEntry *die, bool parse_siblings, bool parse_children)
{
    size_t types_added = 0;
    while (die != NULL)
    {
        bool type_is_new = false;
        if (ParseType(sc, dwarf_cu, die, type_is_new).get())
        {
            if (type_is_new)
                ++types_added;
        }

        if (parse_children && die->HasChildren())
        {
            if (die->Tag() == DW_TAG_subprogram)
            {
                SymbolContext child_sc(sc);
                child_sc.function = sc.comp_unit->FindFunctionByUID(die->GetOffset()).get();
                types_added += ParseTypes(child_sc, dwarf_cu, die->GetFirstChild(), true, true);
            }
            else
                types_added += ParseTypes(sc, dwarf_cu, die->GetFirstChild(), true, true);
        }

        if (parse_siblings)
            die = die->GetSibling();
        else
            die = NULL;
    }
    return types_added;
}


size_t
SymbolFileDWARF::ParseFunctionBlocks (const SymbolContext &sc)
{
    assert(sc.comp_unit && sc.function);
    size_t functions_added = 0;
    DWARFCompileUnit* dwarf_cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());
    if (dwarf_cu)
    {
        dw_offset_t function_die_offset = sc.function->GetID();
        const DWARFDebugInfoEntry *function_die = dwarf_cu->GetDIEPtr(function_die_offset);
        if (function_die)
        {
            ParseFunctionBlocks(sc, Block::RootID, dwarf_cu, function_die, LLDB_INVALID_ADDRESS, false, true);
        }
    }

    return functions_added;
}


size_t
SymbolFileDWARF::ParseTypes (const SymbolContext &sc)
{
    // At least a compile unit must be valid
    assert(sc.comp_unit);
    size_t types_added = 0;
    DWARFCompileUnit* dwarf_cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());
    if (dwarf_cu)
    {
        if (sc.function)
        {
            dw_offset_t function_die_offset = sc.function->GetID();
            const DWARFDebugInfoEntry *func_die = dwarf_cu->GetDIEPtr(function_die_offset);
            if (func_die && func_die->HasChildren())
            {
                types_added = ParseTypes(sc, dwarf_cu, func_die->GetFirstChild(), true, true);
            }
        }
        else
        {
            const DWARFDebugInfoEntry *dwarf_cu_die = dwarf_cu->DIE();
            if (dwarf_cu_die && dwarf_cu_die->HasChildren())
            {
                types_added = ParseTypes(sc, dwarf_cu, dwarf_cu_die->GetFirstChild(), true, true);
            }
        }
    }

    return types_added;
}

size_t
SymbolFileDWARF::ParseVariablesForContext (const SymbolContext& sc)
{
    if (sc.comp_unit != NULL)
    {
        DWARFCompileUnit* dwarf_cu = GetDWARFCompileUnitForUID(sc.comp_unit->GetID());

        if (dwarf_cu == NULL)
            return 0;

        if (sc.function)
        {
            const DWARFDebugInfoEntry *function_die = dwarf_cu->GetDIEPtr(sc.function->GetID());
            return ParseVariables(sc, dwarf_cu, function_die->GetFirstChild(), true, true);
        }
        else if (sc.comp_unit)
        {
            uint32_t vars_added = 0;
            VariableListSP variables (sc.comp_unit->GetVariableList(false));
            
            if (variables.get() == NULL)
            {
                variables.reset(new VariableList());
                sc.comp_unit->SetVariableList(variables);

                // Index if we already haven't to make sure the compile units
                // get indexed and make their global DIE index list
                if (!m_indexed)
                    Index ();

                const size_t num_globals = dwarf_cu->GetNumGlobals();
                for (size_t idx=0; idx<num_globals; ++idx)
                {
                    VariableSP var_sp (ParseVariableDIE(sc, dwarf_cu, dwarf_cu->GetGlobalDIEAtIndex (idx)));
                    if (var_sp)
                    {
                        variables->AddVariable(var_sp);
                        ++vars_added;
                    }
                }
            }
            return vars_added;
        }
    }
    return 0;
}


VariableSP
SymbolFileDWARF::ParseVariableDIE
(
    const SymbolContext& sc,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *die
)
{

    VariableSP var_sp;
    
    const dw_tag_t tag = die->Tag();
    DWARFDebugInfoEntry::Attributes attributes;
    const size_t num_attributes = die->GetAttributes(this, dwarf_cu, attributes);
    if (num_attributes > 0)
    {
        const char *name = NULL;
        Declaration decl;
        uint32_t i;
        TypeSP type_sp;
        Type *var_type = NULL;
        DWARFExpression location;
        bool is_external = false;
        bool is_artificial = false;
        uint32_t accessibility = clang::AS_none;

        for (i=0; i<num_attributes; ++i)
        {
            dw_attr_t attr = attributes.AttributeAtIndex(i);
            DWARFFormValue form_value;
            if (attributes.ExtractFormValueAtIndex(this, i, form_value))
            {
                switch (attr)
                {
                case DW_AT_decl_file:   decl.SetFile(sc.comp_unit->GetSupportFiles().GetFileSpecAtIndex(form_value.Unsigned())); break;
                case DW_AT_decl_line:   decl.SetLine(form_value.Unsigned()); break;
                case DW_AT_decl_column: decl.SetColumn(form_value.Unsigned()); break;
                case DW_AT_name:        name = form_value.AsCString(&get_debug_str_data()); break;
                case DW_AT_type:        var_type = GetUniquedTypeForDIEOffset(form_value.Reference(dwarf_cu), type_sp, 0, 0, false); break;
                case DW_AT_external:    is_external = form_value.Unsigned() != 0; break;
                case DW_AT_location:
                    {
                        if (form_value.BlockData())
                        {
                            const DataExtractor& debug_info_data = get_debug_info_data();

                            uint32_t block_offset = form_value.BlockData() - debug_info_data.GetDataStart();
                            uint32_t block_length = form_value.Unsigned();
                            location.SetOpcodeData(get_debug_info_data(), block_offset, block_length, NULL);
                        }
                        else
                        {
                            const DataExtractor&    debug_loc_data = get_debug_loc_data();
                            const dw_offset_t debug_loc_offset = form_value.Unsigned();

                            size_t loc_list_length = DWARFLocationList::Size(debug_loc_data, debug_loc_offset);
                            if (loc_list_length > 0)
                            {
                                Address base_address(dwarf_cu->GetBaseAddress(), m_obj_file->GetSectionList());
                                location.SetOpcodeData(debug_loc_data, debug_loc_offset, loc_list_length, &base_address);
                            }
                        }
                    }
                    break;

                case DW_AT_artificial:      is_artificial = form_value.Unsigned() != 0; break;
                case DW_AT_accessibility:   accessibility = DwarfToClangAccessibility(form_value.Unsigned()); break;
                case DW_AT_const_value:
                case DW_AT_declaration:
                case DW_AT_description:
                case DW_AT_endianity:
                case DW_AT_segment:
                case DW_AT_start_scope:
                case DW_AT_visibility:
                default:
                case DW_AT_abstract_origin:
                case DW_AT_sibling:
                case DW_AT_specification:
                    break;
                }
            }
        }

        if (location.IsValid())
        {
            assert(var_type != DIE_IS_BEING_PARSED);

            ConstString var_name(name);

            ValueType scope = eValueTypeInvalid;

            const DWARFDebugInfoEntry *sc_parent_die = GetParentSymbolContextDIE(die);
            dw_tag_t parent_tag = sc_parent_die ? sc_parent_die->Tag() : 0;

            if (tag == DW_TAG_formal_parameter)
                scope = eValueTypeVariableArgument;
            else if (is_external || parent_tag == DW_TAG_compile_unit)
                scope = eValueTypeVariableGlobal;
            else
                scope = eValueTypeVariableLocal;

            SymbolContextScope * symbol_context_scope = NULL;
            if (parent_tag == DW_TAG_compile_unit)
            {
                symbol_context_scope = sc.comp_unit;
            }
            else if (sc.function != NULL)
            {
                symbol_context_scope = sc.function->GetBlocks(true).GetBlockByID(sc_parent_die->GetOffset());
                if (symbol_context_scope == NULL)
                    symbol_context_scope = sc.function;
            }

            assert(symbol_context_scope != NULL);
            var_sp.reset (new Variable(die->GetOffset(), 
                                       var_name, 
                                       var_type, 
                                       scope, 
                                       symbol_context_scope, 
                                       &decl, 
                                       location, 
                                       is_external, 
                                       is_artificial));
            const_cast<DWARFDebugInfoEntry*>(die)->SetUserData(var_sp.get());
        }
    }
    return var_sp;
}

size_t
SymbolFileDWARF::ParseVariables
(
    const SymbolContext& sc,
    const DWARFCompileUnit* dwarf_cu,
    const DWARFDebugInfoEntry *orig_die,
    bool parse_siblings,
    bool parse_children,
    VariableList* cc_variable_list
)
{
    if (orig_die == NULL)
        return 0;

    size_t vars_added = 0;
    const DWARFDebugInfoEntry *die = orig_die;
    const DWARFDebugInfoEntry *sc_parent_die = GetParentSymbolContextDIE(orig_die);
    dw_tag_t parent_tag = sc_parent_die ? sc_parent_die->Tag() : 0;
    VariableListSP variables;
    switch (parent_tag)
    {
    case DW_TAG_compile_unit:
        if (sc.comp_unit != NULL)
        {
            variables = sc.comp_unit->GetVariableList(false);
            if (variables.get() == NULL)
            {
                variables.reset(new VariableList());
                sc.comp_unit->SetVariableList(variables);
            }
        }
        else
        {
            assert(!"Parent DIE was a compile unit, yet we don't have a valid compile unit in the symbol context...");
            vars_added = 0;
        }
        break;

    case DW_TAG_subprogram:
    case DW_TAG_inlined_subroutine:
    case DW_TAG_lexical_block:
        if (sc.function != NULL)
        {
            // Check to see if we already have parsed the variables for the given scope
            variables = sc.function->GetBlocks(true).GetVariableList(sc_parent_die->GetOffset(), false, false);
            if (variables.get() == NULL)
            {
                variables.reset(new VariableList());
                sc.function->GetBlocks(true).SetVariableList(sc_parent_die->GetOffset(), variables);
            }
        }
        else
        {
            assert(!"Parent DIE was a function or block, yet we don't have a function in the symbol context...");
            vars_added = 0;
        }
        break;

    default:
        assert(!"Didn't find appropriate parent DIE for variable list...");
        break;
    }

    // We need to have a variable list at this point that we can add variables to
    assert(variables.get());

    while (die != NULL)
    {
        dw_tag_t tag = die->Tag();

        // Check to see if we have already parsed this variable or constant?
        if (die->GetUserData() == NULL)
        {
            // We haven't already parsed it, lets do that now.
            if ((tag == DW_TAG_variable) ||
                (tag == DW_TAG_constant) ||
                (tag == DW_TAG_formal_parameter && sc.function))
            {
                VariableSP var_sp (ParseVariableDIE(sc, dwarf_cu, die));
                if (var_sp)
                {
                    variables->AddVariable(var_sp);
                    ++vars_added;
                }
            }
        }

        bool skip_children = (sc.function == NULL && tag == DW_TAG_subprogram);

        if (!skip_children && parse_children && die->HasChildren())
        {
            vars_added += ParseVariables(sc, dwarf_cu, die->GetFirstChild(), true, true);
            //vars_added += ParseVariables(sc, dwarf_cu, die->GetFirstChild(), parse_siblings, parse_children);
        }

        if (parse_siblings)
            die = die->GetSibling();
        else
            die = NULL;
    }

    if (cc_variable_list)
    {
        cc_variable_list->AddVariables(variables.get());
    }

    return vars_added;
}

//------------------------------------------------------------------
// PluginInterface protocol
//------------------------------------------------------------------
const char *
SymbolFileDWARF::GetPluginName()
{
    return "SymbolFileDWARF";
}

const char *
SymbolFileDWARF::GetShortPluginName()
{
    return GetPluginNameStatic();
}

uint32_t
SymbolFileDWARF::GetPluginVersion()
{
    return 1;
}

void
SymbolFileDWARF::GetPluginCommandHelp (const char *command, Stream *strm)
{
}

Error
SymbolFileDWARF::ExecutePluginCommand (Args &command, Stream *strm)
{
    Error error;
    error.SetErrorString("No plug-in command are currently supported.");
    return error;
}

Log *
SymbolFileDWARF::EnablePluginLogging (Stream *strm, Args &command)
{
    return NULL;
}

