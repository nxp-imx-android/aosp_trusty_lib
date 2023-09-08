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

# temporarily handle both old and new crate paths (b/266828817)
ifneq ($(wildcard external/rust/crates/openssl/.*),)
SRC_DIR := external/rust/crates/openssl
else
SRC_DIR := external/rust/crates/rust-openssl/openssl
endif

MODULE_SRCS := $(SRC_DIR)/src/lib.rs

MODULE_CRATE_NAME := openssl

MODULE_RUST_EDITION := 2018

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/bitflags-rust \
	trusty/user/base/lib/cfg-if-rust \
	trusty/user/base/lib/foreign-types-rust \
	trusty/user/base/lib/libc-rust \
	trusty/user/base/lib/once_cell-rust \
	trusty/user/base/host/openssl-macros \
	trusty/user/base/lib/log-rust \
	trusty/user/base/lib/bssl-sys-rust \

MODULE_RUSTFLAGS += \
	--cfg 'boringssl' \
	--cfg 'soong' \
	--cfg 'feature="unstable_boringssl"' \
	-A unused-imports \
	-A deprecated \
	-A dead-code \

include make/library.mk
