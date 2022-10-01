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

# Recursively ensure that dependencies are built and include their flags +
# includes in the current module's build. This file isolates dependencies from
# their parent module's and the global state, allowing each library to be built
# independently.
#
# args:
# MODULE : Current module name (required)
#
# DEPENDENCY_MODULE : Dependency to build.
#     OR
# EXPORT_DEPENDENCY_MODULE : Dependency to build, flags exported by the
# 		dependency will be re-exported from the current module.
#
# This file extends the current MODULE_* flags with $(DEPENDENCY_MODULE)'s
# MODULE_EXPORT_* flags. In the case of EXPORT_DEPENDENCY_MODULE, the
# dependency's flags will also be appended to the current MODULE_EXPORT_* flags.

ifneq ($(strip $(DEPENDENCY_MODULE)),)
ifneq ($(strip $(EXPORT_DEPENDENCY_MODULE)),)
$(error DEPENDENCY_MODULE and EXPORT_DEPENDENCY_MODULE are mutually exclusive. Please set one or the other when adding dependencies to $(MODULE).)
endif
endif

ifneq ($(strip $(EXPORT_DEPENDENCY_MODULE)),)
DEPENDENCY_MODULE := $(EXPORT_DEPENDENCY_MODULE)
endif

ifeq ($(strip $(DEPENDENCY_MODULE_PATH)),)
DEPENDENCY_MODULE_PATH := $(DEPENDENCY_MODULE)
endif

$(info Building $(DEPENDENCY_MODULE) for $(MODULE))

# SAVED_MODULE_STACK contains a stack of the current dependency chain. We need
# to recursively keep track of this chain so that we can restore our parent
# modules private flags after adding our exported flags (and rules if not
# already emitted).
ifeq ($(filter $(MODULE),$(SAVED_MODULE_STACK)),)
ifeq ($(_MODULES_$(DEPENDENCY_MODULE)),)

# Cache our current state, as it will get wiped out when including dependencies
# in recurse-lib-deps. This must be module-specific as we can have a multi-layer
# chain and these variable are globally scoped.
SAVED_MODULE_STACK := $(SAVED_MODULE_STACK) $(MODULE)
SAVED_$(MODULE)_SRCS := $(MODULE_SRCS)
SAVED_$(MODULE)_SRCS_FIRST := $(MODULE_SRCS_FIRST)
SAVED_$(MODULE)_STATIC_LIB := $(MODULE_STATIC_LIB)
SAVED_$(MODULE)_DEPS := $(MODULE_DEPS)
SAVED_$(MODULE)_LIBRARIES := $(MODULE_LIBRARIES)
SAVED_$(MODULE)_RLIBS := $(MODULE_RLIBS)
SAVED_$(MODULE)_LIBRARY_DEPS := $(MODULE_LIBRARY_DEPS)
SAVED_$(MODULE)_LIBRARY_EXPORTED_DEPS := $(MODULE_LIBRARY_EXPORTED_DEPS)
SAVED_$(MODULE)_LICENSES := $(MODULE_LICENSES)
SAVED_$(MODULE)_ADD_IMPLICIT_DEPS := $(MODULE_ADD_IMPLICIT_DEPS)
SAVED_$(MODULE)_DEFINES := $(MODULE_DEFINES)
SAVED_$(MODULE)_COMPILEFLAGS := $(MODULE_COMPILEFLAGS)
SAVED_$(MODULE)_CONSTANTS := $(MODULE_CONSTANTS)
SAVED_$(MODULE)_CFLAGS := $(MODULE_CFLAGS)
SAVED_$(MODULE)_CPPFLAGS := $(MODULE_CPPFLAGS)
SAVED_$(MODULE)_ASMFLAGS := $(MODULE_ASMFLAGS)
SAVED_$(MODULE)_LDFLAGS := $(MODULE_LDFLAGS)
SAVED_$(MODULE)_RUSTFLAGS := $(MODULE_RUSTFLAGS)
SAVED_$(MODULE)_RUSTDOCFLAGS := $(MODULE_RUSTDOCFLAGS)
SAVED_$(MODULE)_SKIP_DOCS := $(MODULE_SKIP_DOCS)
SAVED_$(MODULE)_DISABLED := $(MODULE_DISABLED)
SAVED_$(MODULE)_RUSTDOC_OBJECT := $(MODULE_RUSTDOC_OBJECT)
SAVED_$(MODULE)_RUST_ENV := $(MODULE_RUST_ENV)
SAVED_$(MODULE)_INCLUDES := $(MODULE_INCLUDES)
SAVED_$(MODULE)_SRCDEPS := $(MODULE_SRCDEPS)
SAVED_$(MODULE)_EXTRA_OBJECTS := $(MODULE_EXTRA_OBJECTS)
SAVED_$(MODULE)_ARM_OVERRIDE_SRCS := $(MODULE_ARM_OVERRIDE_SRCS)
SAVED_$(MODULE)_IS_RUST := $(MODULE_IS_RUST)
SAVED_$(MODULE)_CRATE_NAME := $(MODULE_CRATE_NAME)
SAVED_$(MODULE)_RUST_CRATE_TYPES := $(MODULE_RUST_CRATE_TYPES)
SAVED_$(MODULE)_RUST_HOST_LIB := $(MODULE_RUST_HOST_LIB)
SAVED_$(MODULE)_RUST_EDITION := $(MODULE_RUST_EDITION)
SAVED_$(MODULE)_RUST_TESTS := $(MODULE_RUST_TESTS)
SAVED_$(MODULE)_BINDGEN_ALLOW_VARS := $(MODULE_BINDGEN_ALLOW_VARS)
SAVED_$(MODULE)_BINDGEN_ALLOW_TYPES := $(MODULE_BINDGEN_ALLOW_TYPES)
SAVED_$(MODULE)_BINDGEN_ALLOW_FUNCTIONS := $(MODULE_BINDGEN_ALLOW_FUNCTIONS)
SAVED_$(MODULE)_BINDGEN_CTYPES_PREFIX := $(MODULE_BINDGEN_CTYPES_PREFIX)
SAVED_$(MODULE)_BINDGEN_FLAGS := $(MODULE_BINDGEN_FLAGS)
SAVED_$(MODULE)_BINDGEN_SRC_HEADER := $(MODULE_BINDGEN_SRC_HEADER)
SAVED_$(MODULE)_SDK_LIB_NAME := $(MODULE_SDK_LIB_NAME)
SAVED_$(MODULE)_SDK_LIBS := $(MODULE_SDK_LIBS)
SAVED_$(MODULE)_SDK_HEADER_INSTALL_DIR := $(MODULE_SDK_HEADER_INSTALL_DIR)
SAVED_$(MODULE)_SDK_HEADERS := $(MODULE_SDK_HEADERS)
SAVED_$(MODULE)_TRUSTY_APP := $(TRUSTY_APP)
SAVED_$(MODULE)_TRUSTY_APP_ELF := $(TRUSTY_APP_ELF)
SAVED_$(MODULE)_TRUSTY_APP_NAME := $(TRUSTY_APP_NAME)
SAVED_$(MODULE)_TRUSTY_APP_ALLOCATOR := $(TRUSTY_APP_ALLOCATOR)

# save global variables
SAVED_$(MODULE)_GLOBAL_OPTFLAGS := $(GLOBAL_OPTFLAGS)
SAVED_$(MODULE)_GLOBAL_COMPILEFLAGS := $(GLOBAL_COMPILEFLAGS)
SAVED_$(MODULE)_GLOBAL_CFLAGS := $(GLOBAL_CFLAGS)
SAVED_$(MODULE)_GLOBAL_CPPFLAGS := $(GLOBAL_CPPFLAGS)
SAVED_$(MODULE)_GLOBAL_ASMFLAGS := $(GLOBAL_ASMFLAGS)
SAVED_$(MODULE)_GLOBAL_RUSTFLAGS := $(GLOBAL_RUSTFLAGS)
SAVED_$(MODULE)_GLOBAL_INCLUDES := $(GLOBAL_INCLUDES)
SAVED_$(MODULE)_GLOBAL_DEFINES := $(GLOBAL_DEFINES)

SAVED_$(MODULE)_BUILDDIR := $(BUILDDIR)
SAVED_$(MODULE)_MANIFEST := $(MANIFEST)
SAVED_$(MODULE)_ALLMODULES := $(ALLMODULES)
SAVED_$(MODULE)_ALLMODULE_OBJS := $(ALLMODULE_OBJS)
SAVED_$(MODULE)_ALLOBJS := $(ALLOBJS)

SAVED_$(MODULE)_EXPORT_COMPILEFLAGS := $(MODULE_EXPORT_COMPILEFLAGS)
SAVED_$(MODULE)_EXPORT_CONSTANTS := $(MODULE_EXPORT_CONSTANTS)
SAVED_$(MODULE)_EXPORT_CFLAGS := $(MODULE_EXPORT_CFLAGS)
SAVED_$(MODULE)_EXPORT_CPPFLAGS := $(MODULE_EXPORT_CPPFLAGS)
SAVED_$(MODULE)_EXPORT_ASMFLAGS := $(MODULE_EXPORT_ASMFLAGS)
SAVED_$(MODULE)_EXPORT_LIBRARIES := $(MODULE_EXPORT_LIBRARIES)
SAVED_$(MODULE)_EXPORT_RLIBS := $(MODULE_EXPORT_RLIBS)
SAVED_$(MODULE)_EXPORT_SDK_HEADERS := $(MODULE_EXPORT_SDK_HEADERS)
SAVED_$(MODULE)_EXPORT_LDFLAGS := $(MODULE_EXPORT_LDFLAGS)
SAVED_$(MODULE)_EXPORT_INCLUDES := $(MODULE_EXPORT_INCLUDES)
SAVED_$(MODULE)_EXPORT_EXTRA_OBJECTS := $(MODULE_EXPORT_EXTRA_OBJECTS)

SAVED_$(MODULE)_DEPENDENCY_MODULE := $(DEPENDENCY_MODULE)
SAVED_$(MODULE)_EXPORT_DEPENDENCY_MODULE := $(EXPORT_DEPENDENCY_MODULE)

# If we're using this isolation wrapper, we're using the new module system and
# building in-tree
TRUSTY_NEW_MODULE_SYSTEM := true
TRUSTY_APP_IN_TREE := true

MODULE :=
MODULE_SRCS :=
MODULE_SRCS_FIRST :=
MODULE_STATIC_LIB :=
MODULE_DEPS :=
MODULE_LIBRARIES :=
MODULE_RLIBS :=
MODULE_LIBRARY_DEPS :=
MODULE_LIBRARY_EXPORTED_DEPS :=
MODULE_LICENSES :=
MODULE_ADD_IMPLICIT_DEPS := true
MODULE_DEFINES :=
MODULE_COMPILEFLAGS :=
MODULE_CONSTANTS :=
MODULE_CFLAGS :=
MODULE_CPPFLAGS :=
MODULE_ASMFLAGS :=
MODULE_RUSTFLAGS :=
MODULE_RUSTDOCFLAGS :=
MODULE_SKIP_DOCS :=
MODULE_DISABLED :=
MODULE_RUSTDOC_OBJECT :=
MODULE_RUST_ENV :=
MODULE_LDFLAGS :=
MODULE_INCLUDES :=
MODULE_SRCDEPS :=
MODULE_EXTRA_OBJECTS :=
MODULE_ARM_OVERRIDE_SRCS :=
MODULE_IS_RUST :=
MODULE_CRATE_NAME :=
MODULE_RUST_CRATE_TYPES :=
# Don't clear MODULE_RUST_HOST_LIB here because
# we want it forwarded to dependencies. All
# of them need to be host libraries if the starting
# point was a proc-macro crate.
MODULE_RUST_EDITION :=
MODULE_RUST_TESTS :=
MODULE_BINDGEN_ALLOW_VARS :=
MODULE_BINDGEN_ALLOW_TYPES :=
MODULE_BINDGEN_ALLOW_FUNCTIONS :=
MODULE_BINDGEN_CTYPES_PREFIX :=
MODULE_BINDGEN_FLAGS :=
MODULE_BINDGEN_SRC_HEADER :=
MODULE_SDK_LIB_NAME :=
MODULE_SDK_LIBS :=
MODULE_SDK_HEADER_INSTALL_DIR :=
MODULE_SDK_HEADERS :=
TRUSTY_APP :=
TRUSTY_APP_ELF :=
TRUSTY_APP_ALLOCATOR :=

# Reset global variables
GLOBAL_OPTFLAGS :=
GLOBAL_COMPILEFLAGS :=
GLOBAL_CFLAGS :=
GLOBAL_CPPFLAGS :=
GLOBAL_ASMFLAGS :=
GLOBAL_RUSTFLAGS :=
GLOBAL_INCLUDES :=
GLOBAL_DEFINES :=

MODULE_EXPORT_EXTRA_OBJECTS :=
MODULE_EXPORT_COMPILEFLAGS :=
MODULE_EXPORT_CONSTANTS :=
MODULE_EXPORT_CFLAGS :=
MODULE_EXPORT_CPPFLAGS :=
MODULE_EXPORT_ASMFLAGS :=
MODULE_EXPORT_INCLUDES :=
MODULE_EXPORT_LDFLAGS :=
MODULE_EXPORT_LIBRARIES :=
MODULE_EXPORT_RLIBS :=
MODULE_EXPORT_SDK_HEADERS :=
MODULE_EXPORT_EXTRA_OBJECTS :=

ALLMODULES :=
ALLMODULE_OBJS :=
ALLOBJS :=
MANIFEST :=

EXPORT_DEPENDENCY_MODULE :=

include $(DEPENDENCY_MODULE_PATH)/rules.mk

# Restore state from the saved stack
MODULE := $(lastword $(SAVED_MODULE_STACK))
SAVED_MODULE_STACK := $(filter-out $(MODULE),$(SAVED_MODULE_STACK))
MODULE_SRCS := $(SAVED_$(MODULE)_SRCS)
MODULE_SRCS_FIRST := $(SAVED_$(MODULE)_SRCS_FIRST)
MODULE_STATIC_LIB := $(SAVED_$(MODULE)_STATIC_LIB)
MODULE_DEPS := $(SAVED_$(MODULE)_DEPS)
MODULE_LIBRARIES := $(SAVED_$(MODULE)_LIBRARIES)
MODULE_RLIBS := $(SAVED_$(MODULE)_RLIBS)
MODULE_LIBRARY_DEPS := $(SAVED_$(MODULE)_LIBRARY_DEPS)
MODULE_LIBRARY_EXPORTED_DEPS := $(SAVED_$(MODULE)_LIBRARY_EXPORTED_DEPS)
MODULE_LICENSES := $(SAVED_$(MODULE)_LICENSES)
MODULE_ADD_IMPLICIT_DEPS := $(SAVED_$(MODULE)_ADD_IMPLICIT_DEPS)
MODULE_DEFINES := $(SAVED_$(MODULE)_DEFINES)
MODULE_COMPILEFLAGS := $(SAVED_$(MODULE)_COMPILEFLAGS)
MODULE_CONSTANTS := $(SAVED_$(MODULE)_CONSTANTS)
MODULE_CFLAGS := $(SAVED_$(MODULE)_CFLAGS)
MODULE_CPPFLAGS := $(SAVED_$(MODULE)_CPPFLAGS)
MODULE_ASMFLAGS := $(SAVED_$(MODULE)_ASMFLAGS)
MODULE_RUSTFLAGS := $(SAVED_$(MODULE)_RUSTFLAGS)
MODULE_RUSTDOCFLAGS := $(SAVED_$(MODULE)_RUSTDOCFLAGS)
MODULE_SKIP_DOCS := $(SAVED_$(MODULE)_SKIP_DOCS)
MODULE_DISABLED := $(SAVED_$(MODULE)_DISABLED)
MODULE_RUSTDOC_OBJECT := $(SAVED_$(MODULE)_RUSTDOC_OBJECT)
MODULE_RUST_ENV := $(SAVED_$(MODULE)_RUST_ENV)
MODULE_LDFLAGS := $(SAVED_$(MODULE)_LDFLAGS)
MODULE_INCLUDES := $(SAVED_$(MODULE)_INCLUDES)
MODULE_SRCDEPS := $(SAVED_$(MODULE)_SRCDEPS)
MODULE_EXTRA_OBJECTS := $(SAVED_$(MODULE)_EXTRA_OBJECTS)
MODULE_ARM_OVERRIDE_SRCS := $(SAVED_$(MODULE)_ARM_OVERRIDE_SRCS)
MODULE_IS_RUST := $(SAVED_$(MODULE)_IS_RUST)
MODULE_CRATE_NAME := $(SAVED_$(MODULE)_CRATE_NAME)
MODULE_RUST_CRATE_TYPES := $(SAVED_$(MODULE)_RUST_CRATE_TYPES)
MODULE_RUST_HOST_LIB := $(SAVED_$(MODULE)_RUST_HOST_LIB)
MODULE_RUST_EDITION := $(SAVED_$(MODULE)_RUST_EDITION)
MODULE_RUST_TESTS := $(SAVED_$(MODULE)_RUST_TESTS)
MODULE_BINDGEN_ALLOW_VARS := $(SAVED_$(MODULE)_BINDGEN_ALLOW_VARS)
MODULE_BINDGEN_ALLOW_TYPES := $(SAVED_$(MODULE)_BINDGEN_ALLOW_TYPES)
MODULE_BINDGEN_ALLOW_FUNCTIONS := $(SAVED_$(MODULE)_BINDGEN_ALLOW_FUNCTIONS)
MODULE_BINDGEN_CTYPES_PREFIX := $(SAVED_$(MODULE)_BINDGEN_CTYPES_PREFIX)
MODULE_BINDGEN_FLAGS := $(SAVED_$(MODULE)_BINDGEN_FLAGS)
MODULE_BINDGEN_SRC_HEADER := $(SAVED_$(MODULE)_BINDGEN_SRC_HEADER)
MODULE_SDK_LIB_NAME := $(SAVED_$(MODULE)_SDK_LIB_NAME)
MODULE_SDK_LIBS := $(SAVED_$(MODULE)_SDK_LIBS)
MODULE_SDK_HEADER_INSTALL_DIR := $(SAVED_$(MODULE)_SDK_HEADER_INSTALL_DIR)
MODULE_SDK_HEADERS := $(SAVED_$(MODULE)_SDK_HEADERS)
TRUSTY_APP := $(SAVED_$(MODULE)_TRUSTY_APP)
TRUSTY_APP_ELF := $(SAVED_$(MODULE)_TRUSTY_APP_ELF)
TRUSTY_APP_NAME := $(SAVED_$(MODULE)_TRUSTY_APP_NAME)
TRUSTY_APP_ALLOCATOR := $(SAVED_$(MODULE)_TRUSTY_APP_ALLOCATOR)

# Restore global variables
GLOBAL_OPTFLAGS := $(SAVED_$(MODULE)_GLOBAL_OPTFLAGS)
GLOBAL_COMPILEFLAGS := $(SAVED_$(MODULE)_GLOBAL_COMPILEFLAGS)
GLOBAL_CFLAGS := $(SAVED_$(MODULE)_GLOBAL_CFLAGS)
GLOBAL_CPPFLAGS := $(SAVED_$(MODULE)_GLOBAL_CPPFLAGS)
GLOBAL_ASMFLAGS := $(SAVED_$(MODULE)_GLOBAL_ASMFLAGS)
GLOBAL_RUSTFLAGS := $(SAVED_$(MODULE)_GLOBAL_RUSTFLAGS)
GLOBAL_INCLUDES := $(SAVED_$(MODULE)_GLOBAL_INCLUDES)
GLOBAL_DEFINES := $(SAVED_$(MODULE)_GLOBAL_DEFINES)

BUILDDIR := $(SAVED_$(MODULE)_BUILDDIR)
MANIFEST := $(SAVED_$(MODULE)_MANIFEST)
ALLMODULES := $(SAVED_$(MODULE)_ALLMODULES)
ALLMODULE_OBJS := $(SAVED_$(MODULE)_ALLMODULE_OBJS)
ALLOBJS := $(SAVED_$(MODULE)_ALLOBJS) $(ALLOBJS)

MODULE_EXPORT_COMPILEFLAGS := $(SAVED_$(MODULE)_EXPORT_COMPILEFLAGS)
MODULE_EXPORT_CONSTANTS := $(SAVED_$(MODULE)_EXPORT_CONSTANTS)
MODULE_EXPORT_CFLAGS := $(SAVED_$(MODULE)_EXPORT_CFLAGS)
MODULE_EXPORT_CPPFLAGS := $(SAVED_$(MODULE)_EXPORT_CPPFLAGS)
MODULE_EXPORT_ASMFLAGS := $(SAVED_$(MODULE)_EXPORT_ASMFLAGS)
MODULE_EXPORT_LDFLAGS := $(SAVED_$(MODULE)_EXPORT_LDFLAGS)
MODULE_EXPORT_LIBRARIES := $(SAVED_$(MODULE)_EXPORT_LIBRARIES)
MODULE_EXPORT_RLIBS := $(SAVED_$(MODULE)_EXPORT_RLIBS)
MODULE_EXPORT_SDK_HEADERS := $(SAVED_$(MODULE)_EXPORT_SDK_HEADERS)
MODULE_EXPORT_INCLUDES := $(SAVED_$(MODULE)_EXPORT_INCLUDES)
MODULE_EXPORT_EXTRA_OBJECTS := $(SAVED_$(MODULE)_EXPORT_EXTRA_OBJECTS)

DEPENDENCY_MODULE := $(SAVED_$(MODULE)_DEPENDENCY_MODULE)
EXPORT_DEPENDENCY_MODULE := $(SAVED_$(MODULE)_EXPORT_DEPENDENCY_MODULE)

TRUSTY_NEW_MODULE_SYSTEM :=
TRUSTY_APP_IN_TREE :=

endif # _MODULES_$(DEPENDENCY_MODULE) not set
endif # MODULE not in SAVED_MODULE_STACK

ifneq ($(strip $(EXPORT_DEPENDENCY_MODULE)),)
REEXPORT := true
else
REEXPORT :=
endif

define append-export-flags
$(if $(2),$(eval EXPORT := EXPORT_))\
$(eval MODULE_$(EXPORT)$(1) += $(filter-out $(MODULE_$(EXPORT)$(1)),$(_MODULES_$(DEPENDENCY_MODULE)_$(1))))\
$(eval EXPORT :=)
endef

ifeq ($(filter $(DEPENDENCY_MODULE),$(TRUSTY_SDK_MODULES)),)
# Dependency is NOT part of the SDK

# Only append in-tree headers if this library isn't part of the SDK
$(call append-export-flags,INCLUDES,$(REEXPORT))

ifneq ($(filter $(MODULE),$(TRUSTY_SDK_MODULES)),)
# Module is part of the SDK but our dependency isn't. We need to pick up our
# dependency's headers here because we don't append MODULE_EXPORT_INCLUDES to
# our local includes.
MODULE_INCLUDES += $(filter-out $(MODULE_INCLUDES),$(_MODULES_$(DEPENDENCY_MODULE)_INCLUDES))
endif

endif # MODULE in TRUSTY_SDK_MODULES

# Add our dependencies flags to our exported flags.
# Note that we don't add INCLUDES here. We take care of that above if the
# dependency is not part of the SDK. If it is, we use the SDK sysroot's headers.
$(call append-export-flags,DEFINES,$(REEXPORT))
$(call append-export-flags,COMPILEFLAGS,$(REEXPORT))
$(call append-export-flags,CONSTANTS,$(REEXPORT))
$(call append-export-flags,CFLAGS,$(REEXPORT))
$(call append-export-flags,CPPFLAGS,$(REEXPORT))
$(call append-export-flags,ASMFLAGS,$(REEXPORT))

# We always re-export LDFLAGS and LIBRARIES. This is safe to do in the prescence
# of recursive deps because libraries and link flags are additive and do not
# affect the compiliation. If we have a dependency chain like A -> B -> C -> A,
# we don't need to add A's link flags to C because we will get them in the final
# link directly from A.
$(call append-export-flags,EXTRA_OBJECTS,true)
$(call append-export-flags,LDFLAGS,true)
$(call append-export-flags,LIBRARIES,true)
$(call append-export-flags,RLIBS,true)
$(call append-export-flags,SDK_LIBS,true)

# We always want to make sure that all necessary headers have been copied into
# the SDK before we try to use them. There's no harm in things being copied
# earlier than they are needed.
$(call append-export-flags,SDK_HEADERS,true)

DEPENDENCY_MODULE :=
DEPENDENCY_MODULE_PATH :=
EXPORT_DEPENDENCY_MODULE :=

EXPORT :=
REEXPORT :=
