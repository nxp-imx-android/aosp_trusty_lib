LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_STATIC_LIB := true

LIBCXXABI_DIR = external/libcxxabi

GLOBAL_INCLUDES += $(LIBCXXABI_DIR)/include

MODULE_COMPILEFLAGS += -D_LIBCXXABI_BUILDING_LIBRARY -D_LIBCXXABI_HAS_NO_THREADS

# Required if compiling without exceptions.
MODULE_COMPILEFLAGS += -D_LIBCXXABI_NO_EXCEPTIONS

# Required if compiling without RTTI, but also helps binary size.
MODULE_COMPILEFLAGS += -DLIBCXXABI_SILENT_TERMINATE

MODULE_SRCS := \
	$(LIBCXXABI_DIR)/src/cxa_aux_runtime.cpp \
	$(LIBCXXABI_DIR)/src/cxa_default_handlers.cpp \
	$(LIBCXXABI_DIR)/src/cxa_demangle.cpp \
	$(LIBCXXABI_DIR)/src/cxa_exception_storage.cpp \
	$(LIBCXXABI_DIR)/src/cxa_guard.cpp \
	$(LIBCXXABI_DIR)/src/cxa_handlers.cpp \
	$(LIBCXXABI_DIR)/src/cxa_unexpected.cpp \
	$(LIBCXXABI_DIR)/src/cxa_vector.cpp \
	$(LIBCXXABI_DIR)/src/cxa_virtual.cpp \
	$(LIBCXXABI_DIR)/src/stdlib_exception.cpp \
	$(LIBCXXABI_DIR)/src/stdlib_stdexcept.cpp \
	$(LIBCXXABI_DIR)/src/stdlib_typeinfo.cpp \
	$(LIBCXXABI_DIR)/src/abort_message.cpp \
	$(LIBCXXABI_DIR)/src/fallback_malloc.cpp \

# Exceptions disabled
MODULE_SRCS += \
        $(LIBCXXABI_DIR)/src/cxa_noexception.cpp \

# Files that do not compile without exceptions
# $(LIBCXXABI_DIR)/src/cxa_exception.cpp \
# $(LIBCXXABI_DIR)/src/cxa_personality.cpp \

# Files that do not compile without RTTI
# $(LIBCXXABI_DIR)/src/private_typeinfo.cpp \

include make/module.mk
