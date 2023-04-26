# Copyright (C) 2022 The Android Open Source Project
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

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

BSSL_SRC_DIR := external/boringssl/src

# BoringSSL moved the sources under src/rust/bssl-sys,
# but they used to be one level higher so we use the old path
# for compatibility
BSSL_RUST_DIR := $(BSSL_SRC_DIR)/rust/bssl-sys
ifeq ($(wildcard $(BSSL_RUST_DIR)),)
BSSL_RUST_DIR := $(BSSL_SRC_DIR)/rust
endif

MODULE_EXPORT_INCLUDES := \
	$(BSSL_RUST_DIR)/src \
	$(BSSL_SRC_DIR)/include \

MODULE_SRCS := $(BSSL_RUST_DIR)/rust_wrapper.c

# MODULE_LIBRARY_DEPS := \

include make/library.mk
