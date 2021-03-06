//===-- CommandCompletions.cpp ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


// C Includes
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <glob.h>
#include <pwd.h>
#include <sys/types.h>

// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Interpreter/Args.h"
#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Core/FileSpecList.h"
#include "lldb/Target/Target.h"
#include "lldb/Interpreter/CommandCompletions.h"
#include "lldb/Core/FileSpec.h"


using namespace lldb_private;

CommandCompletions::CommonCompletionElement
CommandCompletions::g_common_completions[] =
{
    {eCustomCompletion,          NULL},
    {eSourceFileCompletion,      CommandCompletions::SourceFiles},
    {eDiskFileCompletion,        CommandCompletions::DiskFiles},
    {eDiskDirectoryCompletion,   CommandCompletions::DiskDirectories},
    {eSymbolCompletion,          CommandCompletions::Symbols},
    {eModuleCompletion,          CommandCompletions::Modules},
    {eNoCompletion,              NULL}      // This one has to be last in the list.
};

bool
CommandCompletions::InvokeCommonCompletionCallbacks 
(
    CommandInterpreter &interpreter,
    uint32_t completion_mask,
    const char *completion_str,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches
)
{
    bool handled = false;

    if (completion_mask & eCustomCompletion)
        return false;

    for (int i = 0; ; i++)
    {
        if (g_common_completions[i].type == eNoCompletion)
            break;
         else if ((g_common_completions[i].type & completion_mask) == g_common_completions[i].type
                   && g_common_completions[i].callback != NULL)
         {
            handled = true;
            g_common_completions[i].callback (interpreter,
                                              completion_str,
                                              match_start_point,
                                              max_return_elements,
                                              searcher,
                                              word_complete,
                                              matches);
        }
    }
    return handled;
}

int
CommandCompletions::SourceFiles 
(
    CommandInterpreter &interpreter,
    const char *partial_file_name,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches
)
{
    word_complete = true;
    // Find some way to switch "include support files..."
    SourceFileCompleter completer (interpreter,
                                   false, 
                                   partial_file_name, 
                                   match_start_point, 
                                   max_return_elements,
                                   matches);

    if (searcher == NULL)
    {
        lldb::TargetSP target_sp = interpreter.GetDebugger().GetCurrentTarget();
        SearchFilter null_searcher (target_sp);
        completer.DoCompletion (&null_searcher);
    }
    else
    {
        completer.DoCompletion (searcher);
    }
    return matches.GetSize();
}

static int
DiskFilesOrDirectories 
(
    const char *partial_file_name,
    bool only_directories,
    bool &saw_directory,
    StringList &matches
)
{
    // I'm going to  use the "glob" function with GLOB_TILDE for user directory expansion.  
    // If it is not defined on your host system, you'll need to implement it yourself...
    
    int partial_name_len = strlen(partial_file_name);
    
    if (partial_name_len >= PATH_MAX)
        return matches.GetSize();
    
    // This copy of the string will be cut up into the directory part, and the remainder.  end_ptr
    // below will point to the place of the remainder in this string.  Then when we've resolved the
    // containing directory, and opened it, we'll read the directory contents and overwrite the
    // partial_name_copy starting from end_ptr with each of the matches.  Thus we will preserve
    // the form the user originally typed.
    
    char partial_name_copy[PATH_MAX];
    memcpy(partial_name_copy, partial_file_name, partial_name_len);
    partial_name_copy[partial_name_len] = '\0';
    
    // We'll need to save a copy of the remainder for comparision, which we do here.
    char remainder[PATH_MAX];
    
    // end_ptr will point past the last / in partial_name_copy, or if there is no slash to the beginning of the string.
    char *end_ptr;
    
    end_ptr = strrchr(partial_name_copy, '/');
    
    // This will store the resolved form of the containing directory
    char containing_part[PATH_MAX];
    
    if (end_ptr == NULL)
    {
        // There's no directory.  If the thing begins with a "~" then this is a bare
        // user name.
        if (*partial_name_copy == '~')
        {
            // Nothing here but the user name.  We could just put a slash on the end, 
            // but for completeness sake we'll resolve the user name and only put a slash
            // on the end if it exists.
            char resolved_username[PATH_MAX];
            size_t resolved_username_len = FileSpec::ResolveUsername (partial_name_copy, resolved_username, 
                                                          sizeof (resolved_username));
                                                          
           // Not sure how this would happen, a username longer than PATH_MAX?  Still...
            if (resolved_username_len >= sizeof (resolved_username))
                return matches.GetSize();
            else if (resolved_username_len == 0)
            {
                // The user name didn't resolve, let's look in the password database for matches.
                // The user name database contains duplicates, and is not in alphabetical order, so
                // we'll use a set to manage that for us.
                
                setpwent();
                struct passwd *user_entry;
                const char *name_start = partial_name_copy + 1;
                std::set<std::string> name_list;
                
                while ((user_entry = getpwent()) != NULL)
                {
                    if (strstr(user_entry->pw_name, name_start) == user_entry->pw_name)
                    {
                        std::string tmp_buf("~");
                        tmp_buf.append(user_entry->pw_name);
                        tmp_buf.push_back('/');
                        name_list.insert(tmp_buf);                    
                        saw_directory = true;
                    }
                }
                std::set<std::string>::iterator pos, end = name_list.end();
                for (pos = name_list.begin(); pos != end; pos++)
                {  
                    matches.AppendString((*pos).c_str());
                }
                return matches.GetSize();
            }    
            
            //The thing exists, put a '/' on the end, and return it...
            // FIXME: complete user names here:
            partial_name_copy[partial_name_len] = '/';
            partial_name_copy[partial_name_len+1] = '\0';
            matches.AppendString(partial_name_copy);
            saw_directory = true;
            return matches.GetSize();
        }
        else
        {
            // The containing part is the CWD, and the whole string is the remainder.
            containing_part[0] = '.';
            containing_part[1] = '\0';
            strcpy(remainder, partial_name_copy);
            end_ptr = partial_name_copy;
        }
    }
    else
    {
        if (end_ptr == partial_name_copy)
        {
            // We're completing a file or directory in the root volume.
            containing_part[0] = '/';
            containing_part[1] = '\0';
        }
        else
        {
            size_t len = end_ptr - partial_name_copy;
            memcpy(containing_part, partial_name_copy, len);
            containing_part[len] = '\0';
        }
        // Push end_ptr past the final "/" and set remainder.
        end_ptr++;
        strcpy(remainder, end_ptr);
    }
    
    // Look for a user name in the containing part, and if it's there, resolve it and stick the
    // result back into the containing_part:
    
    if (*partial_name_copy == '~')
    {
        size_t resolved_username_len = FileSpec::ResolveUsername(containing_part, containing_part, sizeof (containing_part));
        // User name doesn't exist, we're not getting any further...
        if (resolved_username_len == 0 || resolved_username_len >= sizeof (containing_part))
            return matches.GetSize();
    }
    
    // Okay, containing_part is now the directory we want to open and look for files:
    
    DIR *dir_stream;
    
    dir_stream = opendir(containing_part);
    if (dir_stream == NULL)
        return matches.GetSize();
        
    struct dirent *dirent_buf;
    
    size_t baselen = end_ptr - partial_name_copy;
    
    while ((dirent_buf = readdir(dir_stream)) != NULL) 
    {
        char *name = dirent_buf->d_name;
        
        // Omit ".", ".." and any . files if the match string doesn't start with .
        if (name[0] == '.')
        {
            if (name[1] == '\0')
                continue;
            else if (name[1] == '.' && name[2] == '\0')
                continue;
            else if (remainder[0] != '.')
                continue;
        }
        
        // If we found a directory, we put a "/" at the end of the name.
        
        if (remainder[0] == '\0' || strstr(dirent_buf->d_name, remainder) == name)
        {
            if (strlen(name) + baselen >= PATH_MAX)
                continue;
                
            strcpy(end_ptr, name);
            
            bool isa_directory = false;
            if (dirent_buf->d_type & DT_DIR)
                isa_directory = true;
            else if (dirent_buf->d_type & DT_LNK)
            { 
                struct stat stat_buf;
                if ((stat(partial_name_copy, &stat_buf) == 0) && (stat_buf.st_mode & S_IFDIR))
                    isa_directory = true;
            }
            
            if (isa_directory)
            {
                saw_directory = true;
                size_t len = strlen(partial_name_copy);
                partial_name_copy[len] = '/';
                partial_name_copy[len + 1] = '\0';
            }
            if (only_directories && !isa_directory)
                continue;
            matches.AppendString(partial_name_copy);
        }
    }
    
    return matches.GetSize();
}

int
CommandCompletions::DiskFiles 
(
    CommandInterpreter &interpreter,
    const char *partial_file_name,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches
)
{

    int ret_val = DiskFilesOrDirectories (partial_file_name,
                                          false,
                                          word_complete,
                                          matches);
    word_complete = !word_complete;
    return ret_val;
}

int
CommandCompletions::DiskDirectories 
(
    CommandInterpreter &interpreter,
    const char *partial_file_name,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches
)
{
    int ret_val =  DiskFilesOrDirectories (partial_file_name,
                                           true,
                                           word_complete,
                                           matches); 
    word_complete = false;
    return ret_val;
}

int
CommandCompletions::Modules 
(
    CommandInterpreter &interpreter,
    const char *partial_file_name,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches
)
{
    word_complete = true;
    ModuleCompleter completer (interpreter,
                               partial_file_name, 
                               match_start_point, 
                               max_return_elements, 
                               matches);
    
    if (searcher == NULL)
    {
        lldb::TargetSP target_sp = interpreter.GetDebugger().GetCurrentTarget();
        SearchFilter null_searcher (target_sp);
        completer.DoCompletion (&null_searcher);
    }
    else
    {
        completer.DoCompletion (searcher);
    }
    return matches.GetSize();
}

int
CommandCompletions::Symbols 
(
    CommandInterpreter &interpreter,
    const char *partial_file_name,
    int match_start_point,
    int max_return_elements,
    SearchFilter *searcher,
    bool &word_complete,
    StringList &matches)
{
    word_complete = true;
    SymbolCompleter completer (interpreter,
                               partial_file_name, 
                               match_start_point, 
                               max_return_elements, 
                               matches);

    if (searcher == NULL)
    {
        lldb::TargetSP target_sp = interpreter.GetDebugger().GetCurrentTarget();
        SearchFilter null_searcher (target_sp);
        completer.DoCompletion (&null_searcher);
    }
    else
    {
        completer.DoCompletion (searcher);
    }
    return matches.GetSize();
}

CommandCompletions::Completer::Completer 
(
    CommandInterpreter &interpreter,
    const char *completion_str,
    int match_start_point,
    int max_return_elements,
    StringList &matches
) :
    m_interpreter (interpreter),
    m_completion_str (completion_str),
    m_match_start_point (match_start_point),
    m_max_return_elements (max_return_elements),
    m_matches (matches)
{
}

CommandCompletions::Completer::~Completer ()
{

}

//----------------------------------------------------------------------
// SourceFileCompleter
//----------------------------------------------------------------------

CommandCompletions::SourceFileCompleter::SourceFileCompleter 
(
    CommandInterpreter &interpreter,
    bool include_support_files,
    const char *completion_str,
    int match_start_point,
    int max_return_elements,
    StringList &matches
) :
    CommandCompletions::Completer (interpreter, completion_str, match_start_point, max_return_elements, matches),
    m_include_support_files (include_support_files),
    m_matching_files()
{
    FileSpec partial_spec (m_completion_str.c_str());
    m_file_name = partial_spec.GetFilename().GetCString();
    m_dir_name = partial_spec.GetDirectory().GetCString();
}

Searcher::Depth
CommandCompletions::SourceFileCompleter::GetDepth()
{
    return eDepthCompUnit;
}

Searcher::CallbackReturn
CommandCompletions::SourceFileCompleter::SearchCallback (
    SearchFilter &filter,
    SymbolContext &context,
    Address *addr,
    bool complete
)
{
    if (context.comp_unit != NULL)
    {
        if (m_include_support_files)
        {
            FileSpecList supporting_files = context.comp_unit->GetSupportFiles();
            for (size_t sfiles = 0; sfiles < supporting_files.GetSize(); sfiles++)
            {
                const FileSpec &sfile_spec = supporting_files.GetFileSpecAtIndex(sfiles);
                const char *sfile_file_name = sfile_spec.GetFilename().GetCString();
                const char *sfile_dir_name = sfile_spec.GetFilename().GetCString();
                bool match = false;
                if (m_file_name && sfile_file_name
                    && strstr (sfile_file_name, m_file_name) == sfile_file_name)
                    match = true;
                if (match && m_dir_name && sfile_dir_name
                    && strstr (sfile_dir_name, m_dir_name) != sfile_dir_name)
                    match = false;

                if (match)
                {
                    m_matching_files.AppendIfUnique(sfile_spec);
                }
            }

        }
        else
        {
            const char *cur_file_name = context.comp_unit->GetFilename().GetCString();
            const char *cur_dir_name = context.comp_unit->GetDirectory().GetCString();

            bool match = false;
            if (m_file_name && cur_file_name
                && strstr (cur_file_name, m_file_name) == cur_file_name)
                match = true;

            if (match && m_dir_name && cur_dir_name
                && strstr (cur_dir_name, m_dir_name) != cur_dir_name)
                match = false;

            if (match)
            {
                m_matching_files.AppendIfUnique(context.comp_unit);
            }
        }
    }
    return Searcher::eCallbackReturnContinue;
}

size_t
CommandCompletions::SourceFileCompleter::DoCompletion (SearchFilter *filter)
{
    filter->Search (*this);
    // Now convert the filelist to completions:
    for (size_t i = 0; i < m_matching_files.GetSize(); i++)
    {
        m_matches.AppendString (m_matching_files.GetFileSpecAtIndex(i).GetFilename().GetCString());
    }
    return m_matches.GetSize();

}

//----------------------------------------------------------------------
// SymbolCompleter
//----------------------------------------------------------------------

static bool
regex_chars (const char comp)
{
    if (comp == '[' || comp == ']' || comp == '(' || comp == ')')
        return true;
    else
        return false;
}
CommandCompletions::SymbolCompleter::SymbolCompleter 
(
    CommandInterpreter &interpreter,
    const char *completion_str,
    int match_start_point,
    int max_return_elements,
    StringList &matches
) :
    CommandCompletions::Completer (interpreter, completion_str, match_start_point, max_return_elements, matches)
{
    std::string regex_str ("^");
    regex_str.append(completion_str);
    regex_str.append(".*");
    std::string::iterator pos;

    pos = find_if(regex_str.begin(), regex_str.end(), regex_chars);
    while (pos < regex_str.end()) {
        pos = regex_str.insert(pos, '\\');
        pos += 2;
        pos = find_if(pos, regex_str.end(), regex_chars);
    }
    m_regex.Compile(regex_str.c_str());
}

Searcher::Depth
CommandCompletions::SymbolCompleter::GetDepth()
{
    return eDepthModule;
}

Searcher::CallbackReturn
CommandCompletions::SymbolCompleter::SearchCallback (
    SearchFilter &filter,
    SymbolContext &context,
    Address *addr,
    bool complete
)
{
    SymbolContextList func_list;
    SymbolContextList sym_list;

    if (context.module_sp != NULL)
    {
        if (context.module_sp)
        {
            context.module_sp->FindSymbolsMatchingRegExAndType (m_regex, lldb::eSymbolTypeCode, sym_list);
            context.module_sp->FindFunctions (m_regex, true, func_list);
        }

        SymbolContext sc;
        // Now add the functions & symbols to the list - only add if unique:
        for (uint32_t i = 0; i < func_list.GetSize(); i++)
        {
            if (func_list.GetContextAtIndex(i, sc))
            {
                if (sc.function)
                {
                    m_match_set.insert (sc.function->GetMangled().GetDemangledName());
                }
            }
        }

        for (uint32_t i = 0; i < sym_list.GetSize(); i++)
        {
            if (sym_list.GetContextAtIndex(i, sc))
            {
                if (sc.symbol && sc.symbol->GetAddressRangePtr())
                {
                    m_match_set.insert (sc.symbol->GetMangled().GetDemangledName());
                }
            }
        }
    }
    return Searcher::eCallbackReturnContinue;
}

size_t
CommandCompletions::SymbolCompleter::DoCompletion (SearchFilter *filter)
{
    filter->Search (*this);
    collection::iterator pos = m_match_set.begin(), end = m_match_set.end();
    for (pos = m_match_set.begin(); pos != end; pos++)
        m_matches.AppendString((*pos).GetCString());

    return m_matches.GetSize();
}

//----------------------------------------------------------------------
// ModuleCompleter
//----------------------------------------------------------------------
CommandCompletions::ModuleCompleter::ModuleCompleter 
(
    CommandInterpreter &interpreter,
    const char *completion_str,
    int match_start_point,
    int max_return_elements,
    StringList &matches
) :
    CommandCompletions::Completer (interpreter, completion_str, match_start_point, max_return_elements, matches)
{
    FileSpec partial_spec (m_completion_str.c_str());
    m_file_name = partial_spec.GetFilename().GetCString();
    m_dir_name = partial_spec.GetDirectory().GetCString();
}

Searcher::Depth
CommandCompletions::ModuleCompleter::GetDepth()
{
    return eDepthModule;
}

Searcher::CallbackReturn
CommandCompletions::ModuleCompleter::SearchCallback (
    SearchFilter &filter,
    SymbolContext &context,
    Address *addr,
    bool complete
)
{
    if (context.module_sp != NULL)
    {
        const char *cur_file_name = context.module_sp->GetFileSpec().GetFilename().GetCString();
        const char *cur_dir_name = context.module_sp->GetFileSpec().GetDirectory().GetCString();

        bool match = false;
        if (m_file_name && cur_file_name
            && strstr (cur_file_name, m_file_name) == cur_file_name)
            match = true;

        if (match && m_dir_name && cur_dir_name
            && strstr (cur_dir_name, m_dir_name) != cur_dir_name)
            match = false;

        if (match)
        {
            m_matches.AppendString (cur_file_name);
        }
    }
    return Searcher::eCallbackReturnContinue;
}

size_t
CommandCompletions::ModuleCompleter::DoCompletion (SearchFilter *filter)
{
    filter->Search (*this);
    return m_matches.GetSize();
}



