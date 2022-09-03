LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
        $(LOCAL_DIR)/main.cpp \

MODULE_LIBRARY_DEPS += \
        trusty/hardware/nxp/base/lib/hwsecure \
        trusty/user/base/lib/keymaster \
        trusty/user/base/lib/libc-trusty \
        trusty/user/base/lib/libstdc++-trusty \
        trusty/user/base/lib/tipc \

include make/trusted_app.mk
