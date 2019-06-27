LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

# Musl plays tricks with weak symbols to assist dead code elimination.
# By default this build system will "partially link" modules, however, and this
# reduces the effectiveness of weak symbols. Specifically, the linker will see
# the strong symbol in the .o files and references will always resolve to that
# strong symbol. By turning libc into a static library, the strong symbols will
# be pulled into the link only if they are explicitly referenced. This allows
# a weak symbol to provide a dummy implementation unless there is an explicit
# dependancy on the symbol somewhere else in the binary.
MODULE_STATIC_LIB := true

MUSL_DIR := external/trusty/musl

# Fix arch naming differences.
ifeq ($(ARCH),arm64)
MUSL_ARCH := aarch64
else ifeq ($(ARCH),x86)
MUSL_ARCH := x86_64
else
MUSL_ARCH := $(ARCH)
endif


# This eliminate /usr/local/include and /usr/include from includepaths.
# Note that this does NOT eliminate the compiler's builtin include directory,
# which includes header files for vector intrinsics and similar.
# -nostdinc would eliminate all these directories, but we want to keep access
# to the intrinsics for now.
# Also note that the builtin directory will shadow the contents of sysroot.
# To be 100% correct, the libc headers should be in a real sysroot.
GLOBAL_COMPILEFLAGS += --sysroot=fake_sysroot

# Using -isystem instead of -I has two effects. First, these paths will be
# searched after -I.  Second, warnings for these header files will be
# suppressed. Musl's header files are not designed to be warning clean,
# particularly when -Wall is enabled enabled.  Because we're using -Werror,
# we must either patch the header files or use -isystem.
GLOBAL_COMPILEFLAGS += \
	-isystem $(MUSL_DIR)/arch/$(MUSL_ARCH) \
	-isystem $(MUSL_DIR)/arch/generic \
	-isystem $(MUSL_DIR)/include \

# Internal includes. Should mask public includes - but -isystem guarentees this.
MODULE_INCLUDES += \
	$(MUSL_DIR)/src/internal \
	$(MUSL_DIR)/src/include \

# Musl is scrupulous about exposing prototypes and defines based on what
# standard is requested. When compiling C++ code, however, Clang defines
# _GNU_SOURCE because libcxx's header files depend on prototypes that are only
# available with _GNU_SOURCE specified. To avoid skew where prototypes are
# defined for C++ but not C, turn everything on always.
GLOBAL_COMPILEFLAGS += -D_ALL_SOURCE

# Musl declares global variables with names like "index" that can conflict with
# function names when _ALL_SOURCE is turned on. Compile Musl as it expects to be
# compiled.
MODULE_COMPILEFLAGS += -U_ALL_SOURCE -D_XOPEN_SOURCE=700

# libc should be freestanding, but the rest of the app should not be.
MODULE_COMPILEFLAGS += -ffreestanding

# Musl's source is not warning clean. Suppress warnings we know about.
MODULE_COMPILEFLAGS += \
	-Wno-parentheses \
	-Wno-sign-compare \
	-Wno-incompatible-pointer-types-discards-qualifiers \

# Musl is generally not strict about its function prototypes.
# This could be fixed, except for "main". The prototype for main is deliberately
# ill-defined.
MODULE_CFLAGS += -Wno-strict-prototypes


# NOTE eabi_unwind_stubs.c because libgcc pulls in unwinding stuff.
# NOTE using dlmalloc because it's difficult to guarentee Musl's malloc will
# work without mmap.
MODULE_SRCS := \
	external/lk/lib/libc/eabi_unwind_stubs.c \
	$(LOCAL_DIR)/__dso_handle.c \
	$(LOCAL_DIR)/__set_thread_area.c \
	$(LOCAL_DIR)/malloc.c \

# Trusty-specific syscalls
MODULE_SRCS += \
	$(LOCAL_DIR)/ipc.c \
	$(LOCAL_DIR)/mman.c \
	$(LOCAL_DIR)/time.c \
	$(LOCAL_DIR)/trusty_app_mgmt.c \

# Musl
MODULE_SRCS += \
	$(MUSL_DIR)/crt/crt1.c \
	$(MUSL_DIR)/src/env/__environ.c \
	$(MUSL_DIR)/src/env/__init_tls.c \
	$(MUSL_DIR)/src/env/__libc_start_main.c \
	$(MUSL_DIR)/src/internal/defsysinfo.c \
	$(MUSL_DIR)/src/internal/intscan.c \
	$(MUSL_DIR)/src/internal/libc.c \
	$(MUSL_DIR)/src/internal/shgetc.c \
	$(MUSL_DIR)/src/ctype/isdigit.c \
	$(MUSL_DIR)/src/ctype/isxdigit.c \
	$(MUSL_DIR)/src/errno/strerror.c \
	$(MUSL_DIR)/src/errno/__errno_location.c \
	$(MUSL_DIR)/src/exit/abort.c \
	$(MUSL_DIR)/src/exit/assert.c \
	$(MUSL_DIR)/src/exit/atexit.c \
	$(MUSL_DIR)/src/exit/exit.c \
	$(MUSL_DIR)/src/exit/_Exit.c \
	$(MUSL_DIR)/src/locale/__lctrans.c \
	$(MUSL_DIR)/src/prng/rand.c \
	$(MUSL_DIR)/src/stdlib/atoi.c \
	$(MUSL_DIR)/src/stdlib/bsearch.c \
	$(MUSL_DIR)/src/stdlib/strtol.c \
	$(MUSL_DIR)/src/stdlib/qsort.c \
	$(MUSL_DIR)/src/string/memchr.c \
	$(MUSL_DIR)/src/string/memcpy.c \
	$(MUSL_DIR)/src/string/memcmp.c \
	$(MUSL_DIR)/src/string/memmove.c \
	$(MUSL_DIR)/src/string/memset.c \
	$(MUSL_DIR)/src/string/stpcpy.c \
	$(MUSL_DIR)/src/string/strcat.c \
	$(MUSL_DIR)/src/string/strncat.c \
	$(MUSL_DIR)/src/string/strchr.c \
	$(MUSL_DIR)/src/string/strchrnul.c \
	$(MUSL_DIR)/src/string/strcmp.c \
	$(MUSL_DIR)/src/string/strncmp.c \
	$(MUSL_DIR)/src/string/strcpy.c \
	$(MUSL_DIR)/src/string/strlen.c \
	$(MUSL_DIR)/src/string/strnlen.c \
	$(MUSL_DIR)/src/stdio/fflush.c \
	$(MUSL_DIR)/src/stdio/fputc.c \
	$(MUSL_DIR)/src/stdio/fputs.c \
	$(MUSL_DIR)/src/stdio/fprintf.c \
	$(MUSL_DIR)/src/stdio/fwrite.c \
	$(MUSL_DIR)/src/stdio/ofl.c \
	$(MUSL_DIR)/src/stdio/printf.c \
	$(MUSL_DIR)/src/stdio/putchar.c \
	$(MUSL_DIR)/src/stdio/puts.c \
	$(MUSL_DIR)/src/stdio/snprintf.c \
	$(MUSL_DIR)/src/stdio/sprintf.c \
	$(MUSL_DIR)/src/stdio/stderr.c \
	$(MUSL_DIR)/src/stdio/stdout.c \
	$(MUSL_DIR)/src/stdio/vfprintf.c \
	$(MUSL_DIR)/src/stdio/vsnprintf.c \
	$(MUSL_DIR)/src/stdio/vsprintf.c \
	$(MUSL_DIR)/src/stdio/__lockfile.c \
	$(MUSL_DIR)/src/stdio/__overflow.c \
	$(MUSL_DIR)/src/stdio/__stdio_close.c \
	$(MUSL_DIR)/src/stdio/__stdio_exit.c \
	$(MUSL_DIR)/src/stdio/__stdio_write.c \
	$(MUSL_DIR)/src/stdio/__stdio_seek.c \
	$(MUSL_DIR)/src/stdio/__toread.c \
	$(MUSL_DIR)/src/stdio/__towrite.c \
	$(MUSL_DIR)/src/stdio/__uflow.c \
	$(MUSL_DIR)/src/thread/__lock.c \
	$(MUSL_DIR)/src/thread/__wait.c \
	$(MUSL_DIR)/src/thread/default_attr.c \
	$(MUSL_DIR)/src/math/frexpf.c \
	$(MUSL_DIR)/src/math/frexp.c \
	$(MUSL_DIR)/src/math/frexpl.c \
	$(MUSL_DIR)/src/math/__fpclassifyl.c \
	$(MUSL_DIR)/src/math/__signbitl.c \


# Turn on the stack protector, except in libc.
# TODO extract the early startup code from this module and turn on the stack
# protector for most of libc.
GLOBAL_COMPILEFLAGS += -fstack-protector-strong
MODULE_COMPILEFLAGS += -fno-stack-protector
MODULE_SRCS += $(MUSL_DIR)/src/env/__stack_chk_fail.c

# Defined by kernel/lib/ubsan/enable.mk if in use for the build
ifeq ($(UBSAN_ENABLED), true)
MODULE_DEPS += trusty/kernel/lib/ubsan
endif

# Add Trusty libc extensions (separated due to use both in the kernel and here)
MODULE_DEPS += trusty/kernel/lib/libc-ext

# Add dependency on syscall-stubs
include  trusty/user/base/lib/syscall-stubs/add-dependency-inc.mk

include make/module.mk
