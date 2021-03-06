//===-- RegularExpression.cpp -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/RegularExpression.h"
#include <string.h>

using namespace lldb_private;

//----------------------------------------------------------------------
// Default constructor
//----------------------------------------------------------------------
RegularExpression::RegularExpression() :
    m_re(),
    m_comp_err (1),
    m_preg(),
    m_matches()
{
    memset(&m_preg,0,sizeof(m_preg));
}

//----------------------------------------------------------------------
// Constructor that compiles "re" using "flags" and stores the
// resulting compiled regular expression into this object.
//----------------------------------------------------------------------
RegularExpression::RegularExpression(const char* re, int flags) :
    m_re(),
    m_comp_err (1),
    m_preg()
{
    memset(&m_preg,0,sizeof(m_preg));
    Compile(re, flags);
}

//----------------------------------------------------------------------
// Destructor
//
// Any previosuly compiled regular expression contained in this
// object will be freed.
//----------------------------------------------------------------------
RegularExpression::~RegularExpression()
{
    Free();
}

//----------------------------------------------------------------------
// Compile a regular expression using the supplied regular
// expression text and flags. The compied regular expression lives
// in this object so that it can be readily used for regular
// expression matches. Execute() can be called after the regular
// expression is compiled. Any previosuly compiled regular
// expression contained in this object will be freed.
//
// RETURNS
//  True of the refular expression compiles successfully, false
//  otherwise.
//----------------------------------------------------------------------
bool
RegularExpression::Compile(const char* re, int flags)
{
    Free();
    if (re && re[0])
    {
        m_re = re;
        m_comp_err = ::regcomp (&m_preg, re, flags);
    }
    else
    {
        // No valid regular expression
        m_comp_err = 1;
    }

    return m_comp_err == 0;
}

//----------------------------------------------------------------------
// Execute a regular expression match using the compiled regular
// expression that is already in this object against the match
// string "s". If any parens are used for regular expression
// matches "match_count" should indicate the number of regmatch_t
// values that are present in "match_ptr". The regular expression
// will be executed using the "execute_flags".
//----------------------------------------------------------------------
bool
RegularExpression::Execute(const char* s, size_t num_matches, int execute_flags) const
{
    int match_result = 1;
    if (m_comp_err == 0)
    {
        if (num_matches > 0)
            m_matches.resize(num_matches + 1);
        else
            m_matches.clear();

        match_result = ::regexec (&m_preg,
                                  s,
                                  m_matches.size(),
                                  const_cast<regmatch_t *>(m_matches.data()),
                                  execute_flags);
    }
    return match_result == 0;
}

bool
RegularExpression::GetMatchAtIndex (const char* s, uint32_t idx, std::string& match_str) const
{
    if (idx <= m_preg.re_nsub && idx < m_matches.size())
    {
        match_str.assign (s + m_matches[idx].rm_so,
                          m_matches[idx].rm_eo - m_matches[idx].rm_so);
        return true;
    }
    return false;
}


//----------------------------------------------------------------------
// Returns true if the regular expression compiled and is ready
// for execution.
//----------------------------------------------------------------------
bool
RegularExpression::IsValid () const
{
    return m_comp_err == 0;
}

//----------------------------------------------------------------------
// Returns the text that was used to compile the current regular
// expression.
//----------------------------------------------------------------------
const char*
RegularExpression::GetText () const
{
    return m_re.c_str();
}

//----------------------------------------------------------------------
// Free any contained compiled regular expressions.
//----------------------------------------------------------------------
void
RegularExpression::Free()
{
    if (m_comp_err == 0)
    {
        m_re.clear();
        regfree(&m_preg);
        // Set a compile error since we no longer have a valid regex
        m_comp_err = 1;
    }
}
