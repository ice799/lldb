//===-- SBFileSpec.h --------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_SBFileSpec_h_
#define LLDB_SBFileSpec_h_

#include <LLDB/SBDefines.h>

namespace lldb {

class SBFileSpec
{
public:
    SBFileSpec ();

    SBFileSpec (const lldb::SBFileSpec &rhs);

    SBFileSpec (const char *path);

    ~SBFileSpec ();

#ifndef SWIG
    const SBFileSpec &
    operator = (const lldb::SBFileSpec &rhs);
#endif

    bool
    IsValid() const;

    bool
    Exists () const;

    const char *
    GetFileName() const;

    const char *
    GetDirectory() const;

    uint32_t
    GetPath (char *dst_path, size_t dst_len) const;

    static int
    ResolvePath (const char *src_path, char *dst_path, size_t dst_len);

private:
    friend class SBLineEntry;
    friend class SBCompileUnit;
    friend class SBHostOS;
    friend class SBModule;
    friend class SBSourceManager;
    friend class SBTarget;

    void
    SetFileSpec (const lldb_private::FileSpec& fs);
#ifndef SWIG

    const lldb_private::FileSpec *
    operator->() const;

    const lldb_private::FileSpec *
    get() const;

    const lldb_private::FileSpec &
    operator*() const;

    const lldb_private::FileSpec &
    ref() const;

#endif

    std::auto_ptr <lldb_private::FileSpec> m_lldb_object_ap;
};


} // namespace lldb

#endif // LLDB_SBFileSpec_h_
