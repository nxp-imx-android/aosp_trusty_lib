LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

# Needed to assist dead code elimination.
MODULE_STATIC_LIB := true

LIBCXX_DIR = external/libcxx

GLOBAL_INCLUDES += $(LIBCXX_DIR)/include

# The header files change if they're being used to build the library.
# For example, adding "public" methods that are only used internally.
MODULE_CPPFLAGS += -D_LIBCPP_BUILDING_LIBRARY

# libcxx defines fallback functions unless it knows they'll be found in libcxxabi.
MODULE_CPPFLAGS += -DLIBCXX_BUILDING_LIBCXXABI

# Unfortunately these must be global because they change the contents of the header files.
# _LIBCPP_BUILD_STATIC is obviously an issue because it can eliminate a virtual
# function and lead to a missing vtable entry. The others are made global out of
# caution.
GLOBAL_CPPFLAGS += -D_LIBCPP_BUILD_STATIC -D_LIBCPP_HAS_NO_THREADS -D_LIBCPP_HAS_MUSL_LIBC

MODULE_SRCS := \
        $(LIBCXX_DIR)/src/algorithm.cpp \
        $(LIBCXX_DIR)/src/any.cpp \
        $(LIBCXX_DIR)/src/bind.cpp \
        $(LIBCXX_DIR)/src/charconv.cpp \
        $(LIBCXX_DIR)/src/chrono.cpp \
        $(LIBCXX_DIR)/src/condition_variable.cpp \
        $(LIBCXX_DIR)/src/debug.cpp \
        $(LIBCXX_DIR)/src/exception.cpp \
        $(LIBCXX_DIR)/src/future.cpp \
        $(LIBCXX_DIR)/src/hash.cpp \
        $(LIBCXX_DIR)/src/memory.cpp \
        $(LIBCXX_DIR)/src/mutex.cpp \
        $(LIBCXX_DIR)/src/new.cpp \
        $(LIBCXX_DIR)/src/optional.cpp \
        $(LIBCXX_DIR)/src/regex.cpp \
        $(LIBCXX_DIR)/src/shared_mutex.cpp \
        $(LIBCXX_DIR)/src/string.cpp \
        $(LIBCXX_DIR)/src/system_error.cpp \
        $(LIBCXX_DIR)/src/thread.cpp \
        $(LIBCXX_DIR)/src/typeinfo.cpp \
        $(LIBCXX_DIR)/src/utility.cpp \
        $(LIBCXX_DIR)/src/valarray.cpp \
        $(LIBCXX_DIR)/src/variant.cpp \
        $(LIBCXX_DIR)/src/vector.cpp \


# TODO add src/random.cpp when there is support for getting entropy.
# TODO files that require locale support.


MODULE_DEPS := \
        trusty/user/base/lib/libcxxabi-trusty \

include make/module.mk
