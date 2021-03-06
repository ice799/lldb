//===-- AddressResolver.h ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_AddressResolver_h_
#define liblldb_AddressResolver_h_

#include <vector>

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private.h"
#include "lldb/Core/Address.h"
#include "lldb/Core/AddressRange.h"
#include "lldb/Core/FileSpec.h"
#include "lldb/Core/RegularExpression.h"
#include "lldb/Core/SearchFilter.h"
#include "lldb/Core/ConstString.h"

namespace lldb_private {

//----------------------------------------------------------------------
/// @class AddressResolver AddressResolver.h "lldb/Core/AddressResolver.h"
/// @brief This class works with SearchFilter to resolve function names and
/// source file locations to their concrete addresses.
//----------------------------------------------------------------------

//----------------------------------------------------------------------
/// General Outline:
/// The AddressResolver is a Searcher.  In that protocol,
/// the SearchFilter asks the question "At what depth of the symbol context
/// descent do you want your callback to get called?" of the filter.  The resolver
/// answers this question (in the GetDepth method) and provides the resolution callback.
//----------------------------------------------------------------------

class AddressResolver :
   public Searcher
{
public:

    typedef enum
    {
        Exact,
        Regexp,
        Glob
    } MatchType;


    AddressResolver ();

    virtual
    ~AddressResolver ();

    virtual void
    ResolveAddress (SearchFilter &filter);

    virtual void
    ResolveAddressInModules (SearchFilter &filter,
                             ModuleList &modules);

    virtual void
    GetDescription (Stream *s) = 0;

    std::vector<AddressRange> &
    GetAddressRanges ();

    size_t
    GetNumberOfAddresses ();

    AddressRange &
    GetAddressRangeAtIndex (size_t idx);

protected:

    std::vector<AddressRange> m_address_ranges;

private:
    DISALLOW_COPY_AND_ASSIGN(AddressResolver);
};

} // namespace lldb_private

#endif  // liblldb_AddressResolver_h_
