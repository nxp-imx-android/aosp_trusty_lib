LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

LIBCXX_DIR = external/libcxx

GLOBAL_INCLUDES += $(LIBCXX_DIR)/include

# The header files change if they're being used to build the library.
# For example, adding "public" methods that are only used internally.
MODULE_COMPILEFLAGS += -D_LIBCPP_BUILDING_LIBRARY

MODULE_SRCS := \
        $(LIBCXX_DIR)/src/memory.cpp \
        $(LIBCXX_DIR)/src/new.cpp \
        $(LIBCXX_DIR)/src/string.cpp \

include make/module.mk
