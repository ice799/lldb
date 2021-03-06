##===- source/Makefile -------------------------------------*- Makefile -*-===##
# 
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
# 
##===----------------------------------------------------------------------===##

LEVEL := ../../..
LLDB_LEVEL := ..

LIBRARYNAME = lldb

#EXPORTED_SYMBOL_FILE = $(PROJ_SRC_DIR)/../resources/lldb-framework-exports
NO_BUILD_ARCHIVE = 1
LINK_LIBS_IN_SHARED = 1
SHARED_LIBRARY = 1

# Include all archives in liblldb.a files
USEDLIBS = lldbAPI.a \
	lldbBreakpoint.a \
	lldbCommands.a \
	lldbCore.a \
	lldbExpression.a \
	lldbHostPosix.a \
	lldbInitAndLog.a \
	lldbInterpreter.a \
	lldbPluginABIMacOSX_i386.a \
	lldbPluginABISysV_x86_64.a \
	lldbPluginDisassemblerLLVM.a \
	lldbPluginObjectContainerBSDArchive.a \
	lldbPluginObjectFileELF.a \
	lldbPluginSymbolFileDWARF.a \
	lldbPluginSymbolFileSymtab.a \
	lldbPluginSymbolVendorMacOSX.a \
	lldbSymbol.a \
	lldbTarget.a \
	lldbUtility.a \
	plugin_llvmc_Base.a \
	plugin_llvmc_Clang.a \
	clangAnalysis.a \
	clangAST.a \
	clangBasic.a \
	clangCodeGen.a \
	clangFrontend.a \
	clangDriver.a \
	clangIndex.a \
	clangLex.a \
	clangRewrite.a \
	clangParse.a \
	clangSema.a \
	CompilerDriver.a \
	EnhancedDisassembly.a \
	clangChecker.a

include $(LLDB_LEVEL)/../../Makefile.config

LINK_COMPONENTS := $(TARGETS_TO_BUILD) asmparser bitreader bitwriter codegen \
                   ipo selectiondag jit

ifeq ($(HOST_OS),Darwin)
  USEDLIBS += lldbHostMacOSX.a \
              lldbPluginDynamicLoaderMacOSX.a \
              lldbPluginObjectContainerUniversalMachO.a \
              lldbPluginObjectFileMachO.a \
              lldbPluginProcessGDBRemote.a \
              lldbPluginUtility.a
endif

ifeq ($(HOST_OS),Linux)
  USEDLIBS += lldbHostLinux.a
endif

include $(LEVEL)/Makefile.common

ifeq ($(HOST_OS),Darwin)
    LLVMLibsOptions += -Wl,-all_load
    # set dylib internal version number to llvmCore submission number
    ifdef LLDB_SUBMIT_VERSION
        LLVMLibsOptions += -Wl,-current_version \
                           -Wl,$(LLDB_SUBMIT_VERSION).$(LLDB_SUBMIT_SUBVERSION) \
                           -Wl,-compatibility_version -Wl,1
    endif
    # extra options to override libtool defaults 
    LLVMLibsOptions += -avoid-version
	LLVMLibsOptions += -F/System/Library/Frameworks -F/System/Library/PrivateFrameworks
	LLVMLibsOptions += -framework Foundation -framework CoreFoundation 
	LLVMLibsOptions += -framework DebugSymbols -lpython2.6 -lobjc
	LLVMLibsOptions += -Wl,-exported_symbols_list -Wl,"$(PROJ_SRC_DIR)/$(LLDB_LEVEL)/resources/lldb-framework-exports" 
    # Mac OS X 10.4 and earlier tools do not allow a second -install_name on command line
    DARWIN_VERS := $(shell echo $(TARGET_TRIPLE) | sed 's/.*darwin\([0-9]*\).*/\1/')
    ifneq ($(DARWIN_VERS),8)
       LLVMLibsOptions  += -no-undefined -Wl,-install_name \
                           -Wl,"@executable_path/../lib/lib$(LIBRARYNAME)$(SHLIBEXT)"
    endif
endif

ifeq ($(HOST_OS), Linux)
    # Include everything from the .a's into the shared library.
    ProjLibsOptions := -Wl,--whole-archive $(ProjLibsOptions) \
                       -Wl,--no-whole-archive
    # Don't allow unresolved symbols.
    LLVMLibsOptions += -Wl,--no-undefined
    # Link in python
    LD.Flags += -lpython2.6
endif
