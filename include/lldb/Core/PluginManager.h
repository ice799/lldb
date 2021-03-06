//===-- PluginManager.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#ifndef liblldb_PluginManager_h_
#define liblldb_PluginManager_h_

#include "lldb/lldb-private.h"

namespace lldb_private {

class PluginManager
{
public:
    //------------------------------------------------------------------
    // ABI
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    ABICreateInstance create_callback);

    static bool
    UnregisterPlugin (ABICreateInstance create_callback);

    static ABICreateInstance
    GetABICreateCallbackAtIndex (uint32_t idx);

    static ABICreateInstance
    GetABICreateCallbackForPluginName (const char *name);


    //------------------------------------------------------------------
    // Disassembler
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    DisassemblerCreateInstance create_callback);

    static bool
    UnregisterPlugin (DisassemblerCreateInstance create_callback);

    static DisassemblerCreateInstance
    GetDisassemblerCreateCallbackAtIndex (uint32_t idx);

    static DisassemblerCreateInstance
    GetDisassemblerCreateCallbackForPluginName (const char *name);


    //------------------------------------------------------------------
    // DynamicLoader
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    DynamicLoaderCreateInstance create_callback);

    static bool
    UnregisterPlugin (DynamicLoaderCreateInstance create_callback);

    static DynamicLoaderCreateInstance
    GetDynamicLoaderCreateCallbackAtIndex (uint32_t idx);

    static DynamicLoaderCreateInstance
    GetDynamicLoaderCreateCallbackForPluginName (const char *name);


    //------------------------------------------------------------------
    // ObjectFile
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    ObjectFileCreateInstance create_callback);

    static bool
    UnregisterPlugin (ObjectFileCreateInstance create_callback);

    static ObjectFileCreateInstance
    GetObjectFileCreateCallbackAtIndex (uint32_t idx);

    static ObjectFileCreateInstance
    GetObjectFileCreateCallbackForPluginName (const char *name);


    //------------------------------------------------------------------
    // ObjectContainer
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    ObjectContainerCreateInstance create_callback);

    static bool
    UnregisterPlugin (ObjectContainerCreateInstance create_callback);

    static ObjectContainerCreateInstance
    GetObjectContainerCreateCallbackAtIndex (uint32_t idx);

    static ObjectContainerCreateInstance
    GetObjectContainerCreateCallbackForPluginName (const char *name);

    //------------------------------------------------------------------
    // LogChannel
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    LogChannelCreateInstance create_callback);

    static bool
    UnregisterPlugin (LogChannelCreateInstance create_callback);

    static LogChannelCreateInstance
    GetLogChannelCreateCallbackAtIndex (uint32_t idx);

    static LogChannelCreateInstance
    GetLogChannelCreateCallbackForPluginName (const char *name);

    static const char *
    GetLogChannelCreateNameAtIndex (uint32_t idx);

    //------------------------------------------------------------------
    // Process
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    ProcessCreateInstance create_callback);

    static bool
    UnregisterPlugin (ProcessCreateInstance create_callback);

    static ProcessCreateInstance
    GetProcessCreateCallbackAtIndex (uint32_t idx);

    static ProcessCreateInstance
    GetProcessCreateCallbackForPluginName (const char *name);

    //------------------------------------------------------------------
    // SymbolFile
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    SymbolFileCreateInstance create_callback);

    static bool
    UnregisterPlugin (SymbolFileCreateInstance create_callback);

    static SymbolFileCreateInstance
    GetSymbolFileCreateCallbackAtIndex (uint32_t idx);

    static SymbolFileCreateInstance
    GetSymbolFileCreateCallbackForPluginName (const char *name);


    //------------------------------------------------------------------
    // SymbolVendor
    //------------------------------------------------------------------
    static bool
    RegisterPlugin (const char *name,
                    const char *description,
                    SymbolVendorCreateInstance create_callback);

    static bool
    UnregisterPlugin (SymbolVendorCreateInstance create_callback);

    static SymbolVendorCreateInstance
    GetSymbolVendorCreateCallbackAtIndex (uint32_t idx);

    static SymbolVendorCreateInstance
    GetSymbolVendorCreateCallbackForPluginName (const char *name);
};


} // namespace lldb_private

#endif  // liblldb_PluginManager_h_
