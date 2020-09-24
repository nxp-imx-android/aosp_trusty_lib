#
# Copyright (c) 2020, Google, Inc. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Build a userspace library for Trusty
#
# args:
# MODULE : module name (required)
# MODULE_SRCS : list of source files, local path (not required for header-only
# 		libraries)
# MODULE_LIBRARY_DEPS : libraries that this module depends on. These libraries
# 		must be built using the new library.mk system (i.e. include
# 		make/library.mk at the end of the library's rules)
# MODULE_DEPS : legacy dependencies that do not use the new library.mk system.
# 		These dependencies will be built exclusively for this module and not
# 		shared with other modules). Do not use this for library dependencies
# 		compatible with library.mk, instead use MODULE_LIBRARY_DEPS.
# MODULE_ADD_IMPLICIT_DEPS : Add basic libraries to MODULE_LIBRARY_DEPS.
# 		Defaults to true. (currently adds libc-trusty)
# MODULE_DEFINES : #defines local to this module
# MODULE_COMPILEFLAGS : COMPILEFLAGS local to this module
# MODULE_CFLAGS : CFLAGS local to this module
# MODULE_CPPFLAGS : CPPFLAGS local to this module
# MODULE_ASMFLAGS : ASMFLAGS local to this module
# MODULE_INCLUDES : include directories local to this module
# MODULE_SRCDEPS : extra dependencies that all of this module's files depend on
# MODULE_EXTRA_OBJECTS : extra .o files that should be linked with the module
# MODULE_ARM_OVERRIDE_SRCS : list of source files, local path that should be
# 		force compiled with ARM (if applicable)
#
# Exported flags:
# The following args are the same as their corresponding variables above, but
# will be exported to all users of this library. These flags are also prepended
# to this module's local flags. To override an exported flag, add the
# corresponding override to e.g. MODULE_COMPILEFLAGS.
#
# MODULE_EXPORT_DEFINES
# MODULE_EXPORT_COMPILEFLAGS
# MODULE_EXPORT_CFLAGS
# MODULE_EXPORT_CPPFLAGS
# MODULE_EXPORT_ASMFLAGS
# MODULE_EXPORT_INCLUDES

# the minimum library rules.mk file is as follows:
#
# LOCAL_DIR := $(GET_LOCAL_DIR)
# MODULE := $(LOCAL_DIR)
#
# MODULE_SRCS := $(LOCAL_DIR)/source_file.c
#
# include make/library.mk

ifeq ($(call TOBOOL,$(TRUSTY_NEW_MODULE_SYSTEM)),false)

$(info Building kernel library: $(MODULE))

GLOBAL_INCLUDES += $(MODULE_EXPORT_INCLUDES)

# Building for the kernel, turn off independent library build and fall back to
# lk module system.
include make/module.mk

else  # TRUSTY_NEW_MODULE_SYSTEM is true

# Build with the new module system. Currently, the Trusty userspace libraries
# and apps use the new module system, as does the bootloader/test-runner binary.
$(info Building library or app: $(MODULE))

# Reset new module system marker. This will be set again in dependencies by
# userspace_recurse.mk
TRUSTY_NEW_MODULE_SYSTEM :=

ifeq ($(call TOBOOL,$(TRUSTY_APP)),false)
BUILDDIR := $(TRUSTY_LIBRARY_BUILDDIR)
endif

# Add any common flags to the module
include make/common_flags.mk

ifneq ($(GLOBAL_OPTFLAGS),)
$(error $(MODULE) has modified GLOBAL_OPTFLAGS, this variable is deprecated)
endif
ifneq ($(GLOBAL_COMPILEFLAGS),)
$(error $(MODULE) has modified GLOBAL_COMPILEFLAGS, this variable is deprecated, please use MODULE_EXPORT_COMPILEFLAGS)
endif
ifneq ($(GLOBAL_CFLAGS),)
$(error $(MODULE) has modified GLOBAL_CFLAGS, this variable is deprecated, please use MODULE_EXPORT_CFLAGS)
endif
ifneq ($(GLOBAL_CPPFLAGS),)
$(error $(MODULE) has modified GLOBAL_CPPFLAGS, this variable is deprecated, please use MODULE_EXPORT_CPPFLAGS)
endif
ifneq ($(GLOBAL_ASMFLAGS),)
$(error $(MODULE) has modified GLOBAL_ASMFLAGS, this variable is deprecated, please use MODULE_EXPORT_ASMFLAGS)
endif
ifneq ($(GLOBAL_DEFINES),)
$(error $(MODULE) has modified GLOBAL_DEFINES, this variable is deprecated, please use MODULE_EXPORT_DEFINES)
endif
ifneq ($(GLOBAL_INCLUDES),)
$(error $(MODULE) has modified GLOBAL_INCLUDES, this variable is deprecated, please use MODULE_EXPORT_INCLUDES)
endif
ifneq ($(MODULE_OPTFLAGS),)
$(error $(MODULE) sets MODULE_OPTFLAGS, which is deprecated. Please move these flags to another variable.)
endif

ifneq ($(strip $(MODULE_DEPS)),)
$(warning $(MODULE) is a userspace library module but has deprecated MODULE_DEPS: $(MODULE_DEPS).)
endif

# Register the module in a global registry. This is used to avoid repeatedly
# generating rules for this module from modules that depend on it.
_MODULES_$(MODULE) := T

# Cache exported flags for use in modules that depend on this library.
_MODULES_$(MODULE)_DEFINES := $(MODULE_EXPORT_DEFINES)
_MODULES_$(MODULE)_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS)
_MODULES_$(MODULE)_CFLAGS := $(MODULE_EXPORT_CFLAGS)
_MODULES_$(MODULE)_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS)
_MODULES_$(MODULE)_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS)
_MODULES_$(MODULE)_INCLUDES := $(MODULE_EXPORT_INCLUDES)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)

DEPENDENCY_MODULE :=

# Recurse into dependencies that this module re-exports flags from. This needs
# to happen before we recurse into regular dependencies in the case of recursive
# dependencies, which need to pick up this module's re-exported flags.
$(foreach dep,$(sort $(MODULE_LIBRARY_EXPORTED_DEPS)),\
	$(eval EXPORT_DEPENDENCY_MODULE := $(dep))\
	$(eval include make/userspace_recurse.mk))

# Re-cache exported flags after adding any flags from exported deps
_MODULES_$(MODULE)_DEFINES := $(MODULE_EXPORT_DEFINES)
_MODULES_$(MODULE)_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS)
_MODULES_$(MODULE)_CFLAGS := $(MODULE_EXPORT_CFLAGS)
_MODULES_$(MODULE)_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS)
_MODULES_$(MODULE)_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS)
_MODULES_$(MODULE)_INCLUDES := $(MODULE_EXPORT_INCLUDES)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)

# We need to avoid duplicate dependencies here, so we use the sort function
# which also de-duplicates.
$(foreach dep,$(sort $(MODULE_LIBRARY_DEPS)),\
	$(eval DEPENDENCY_MODULE := $(dep))\
	$(eval include make/userspace_recurse.mk))


ifneq ($(MODULE_SRCS)$(MODULE_SRCS_FIRST),)
# Not a header-only library, so we need to build the source files

# Save our current module because module.mk clears it.
LIB_SAVED_MODULE := $(MODULE)

ALLMODULE_OBJS :=

include make/module.mk

# Handle any MODULE_DEPS
include make/recurse.mk

MODULE_EXPORT_OBJECTS += $(ALLMODULE_OBJS)
ALLMODULE_OBJS := $(ALLMODULE_OBJS) $(filter-out $(ALLMODULE_OBJS),$(MODULE_EXPORT_OBJECTS))
MODULE := $(LIB_SAVED_MODULE)

ifeq ($(call TOBOOL,$(CLANGBUILD)), true)
$(BUILDDIR)/%: CC := $(CCACHE) $(CLANG_BINDIR)/clang
else
$(BUILDDIR)/%: CC := $(CCACHE) $(ARCH_$(ARCH)_TOOLCHAIN_PREFIX)gcc
endif
$(BUILDDIR)/%.o: GLOBAL_OPTFLAGS := $(GLOBAL_SHARED_OPTFLAGS) $(GLOBAL_USER_OPTFLAGS) $(ARCH_OPTFLAGS)
$(BUILDDIR)/%.o: GLOBAL_COMPILEFLAGS := $(GLOBAL_SHARED_COMPILEFLAGS) $(GLOBAL_USER_COMPILEFLAGS)
$(BUILDDIR)/%.o: GLOBAL_CFLAGS   := $(GLOBAL_SHARED_CFLAGS) $(GLOBAL_USER_CFLAGS)
$(BUILDDIR)/%.o: GLOBAL_CPPFLAGS := $(GLOBAL_SHARED_CPPFLAGS) $(GLOBAL_USER_CPPFLAGS)
$(BUILDDIR)/%.o: GLOBAL_ASMFLAGS := $(GLOBAL_SHARED_ASMFLAGS) $(GLOBAL_USER_ASMFLAGS)
$(BUILDDIR)/%.o: GLOBAL_INCLUDES := $(addprefix -I,$(GLOBAL_UAPI_INCLUDES) $(GLOBAL_SHARED_INCLUDES) $(GLOBAL_USER_INCLUDES))
$(BUILDDIR)/%.o: ARCH_COMPILEFLAGS := $(ARCH_$(ARCH)_COMPILEFLAGS)
$(BUILDDIR)/%.o: ARCH_CFLAGS := $(ARCH_$(ARCH)_CFLAGS)
$(BUILDDIR)/%.o: THUMBCFLAGS := $(ARCH_$(ARCH)_THUMBCFLAGS)
$(BUILDDIR)/%.o: ARCH_CPPFLAGS := $(ARCH_$(ARCH)_CPPFLAGS)
$(BUILDDIR)/%.o: ARCH_ASMFLAGS := $(ARCH_$(ARCH)_ASMFLAGS)

LIBRARY_ARCHIVE := $(filter %.mod.a,$(ALLMODULE_OBJS))

MODULE_EXPORT_LIBRARIES += $(LIBRARY_ARCHIVE)
MODULE_EXPORT_EXTRA_OBJECTS := $(filter-out $(LIBRARY_ARCHIVE),$(ALLMODULE_OBJS))

# Append dependency libraries into ALLMODULE_OBJS.
ALLMODULE_OBJS := $(ALLMODULE_OBJS) $(filter-out $(ALLMODULE_OBJS),$(MODULE_LIBRARIES))

endif # MODULE is not a header-only library

_MODULES_$(MODULE)_LIBRARIES := $(MODULE_EXPORT_LIBRARIES)
_MODULES_$(MODULE)_EXTRA_OBJECTS := $(MODULE_EXPORT_EXTRA_OBJECTS)
_MODULES_$(MODULE)_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)

endif # building userspace module

# Reset all variables for the next module
MODULE :=
MODULE_LIBRARY_DEPS :=
MODULE_LIBRARY_EXPORTED_DEPS :=
MODULE_LIBRARIES :=
LIB_SAVED_MODULE :=
LIB_SAVED_ALLMODULE_OBJS :=

MODULE_EXPORT_LIBRARIES :=
MODULE_EXPORT_EXTRA_OBJECTS :=
MODULE_EXPORT_DEFINES :=
MODULE_EXPORT_COMPILEFLAGS :=
MODULE_EXPORT_CFLAGS :=
MODULE_EXPORT_CPPFLAGS :=
MODULE_EXPORT_ASMFLAGS :=
MODULE_EXPORT_INCLUDES :=
MODULE_EXPORT_LDFLAGS :=
