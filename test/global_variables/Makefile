#----------------------------------------------------------------------
# Fill in the source files to build
#----------------------------------------------------------------------
C_SOURCES :=main.c
CXX_SOURCES :=
OBJC_SOURCES :=
OBJCXX_SOURCES :=

# Uncomment line below for debugging shell commands
# SHELL = /bin/sh -x

#----------------------------------------------------------------------
# Change any build/tool options needed
#----------------------------------------------------------------------
DS := dsymutil
DSFLAGS =
CFLAGS ?=-arch x86_64 -gdwarf-2 -O0
CPLUSPLUSFLAGS +=$(CFLAGS)
CPPFLAGS +=$(CFLAGS)
LD = gcc
LDFLAGS = $(CFLAGS)
OBJECTS =
EXE=a.out
DSYM=$(EXE).dSYM

#----------------------------------------------------------------------
# dylib settings
#----------------------------------------------------------------------
DYLIB_NAME=a
DYLIB_BASENAME=lib$(DYLIB_NAME).dylib
DYLIB_C_SOURCES :=a.c
ifneq "$(strip $(DYLIB_C_SOURCES))" ""
	DYLIB_OBJECTS +=$(strip $(DYLIB_C_SOURCES:.c=.o))
endif


#----------------------------------------------------------------------
# Check if we have any C source files
#----------------------------------------------------------------------
ifneq "$(strip $(C_SOURCES))" ""
	OBJECTS +=$(strip $(C_SOURCES:.c=.o))
endif


#----------------------------------------------------------------------
# Check if we have any C++ source files
#----------------------------------------------------------------------
ifneq "$(strip $(CXX_SOURCES))" ""
	OBJECTS +=$(strip $(CXX_SOURCES:.cpp=.o))
	LD = g++
endif

#----------------------------------------------------------------------
# Check if we have any ObjC source files
#----------------------------------------------------------------------
ifneq "$(strip $(OBJC_SOURCES))" ""
	OBJECTS +=$(strip $(OBJC_SOURCES:.m=.o))
	LDFLAGS +=-lobjc
endif

#----------------------------------------------------------------------
# Check if we have any ObjC++ source files
#----------------------------------------------------------------------
ifneq "$(strip $(OBJCXX_SOURCES))" ""
	OBJECTS +=$(strip $(OBJCXX_SOURCES:.mm=.o))
	LD = g++
	ifeq $(findstring lobjc,$(LDFLAGS)) ""
		LDFLAGS +=-lobjc
	endif
endif


#----------------------------------------------------------------------
# Make the dSYM file from the executable
#----------------------------------------------------------------------
$(DSYM) : $(EXE)
	$(DS) $(DSFLAGS) -o "$(DSYM)" "$(EXE)"

#----------------------------------------------------------------------
# Compile the executable from all the objects (default rule) with no
# dsym file.
#----------------------------------------------------------------------
$(EXE) : $(OBJECTS) $(DYLIB_BASENAME)
	$(LD) $(LDFLAGS) $(OBJECTS) -L. -l$(DYLIB_NAME) -o "$(EXE)"

#----------------------------------------------------------------------
# Make the dylib
#----------------------------------------------------------------------
$(DYLIB_BASENAME) : $(DYLIB_OBJECTS)
	$(LD) $(LDFLAGS) $(DYLIB_OBJECTS) -install_name "@executable_path/$(DYLIB_BASENAME)" -dynamiclib -o "$(DYLIB_BASENAME)"

#----------------------------------------------------------------------
# Automatic variables based on items already entered. Below we create
# an objects lists from the list of sources by replacing all entries
# that end with .c with .o, and we also create a list of prerequisite
# files by replacing all .c files with .d.
#----------------------------------------------------------------------
PREREQS := $(OBJECTS:.o=.d)

#----------------------------------------------------------------------
# Rule for Generating Prerequisites Automatically using .d files and
# the compiler -MM option. The -M option will list all system headers,
# and the -MM option will list all non-system dependencies.
#----------------------------------------------------------------------
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.d: %.cpp
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.d: %.m
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.d: %.mm
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

#----------------------------------------------------------------------
# Include all of the makefiles for each source file so we don't have
# to manually track all of the prerequisites for each source file.
#----------------------------------------------------------------------
sinclude $(PREREQS)

.PHONY: clean
dsym:	$(DSYM)
all:	$(EXE) $(DSYM)
clean:
	rm -rf "$(EXE)" "$(DSYM)" $(OBJECTS) $(PREREQS) $(DYLIB_OBJECTS) $(DYLIB_BASENAME) $(DYLIB_BASENAME).dSYM



