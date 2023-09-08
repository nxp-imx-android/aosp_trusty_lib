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

MODULE_SRCS := $(LOCAL_DIR)/src/lib.rs

MODULE_CRATE_NAME := storage

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/storage \
	trusty/user/base/lib/trusty-sys \
	trusty/user/base/lib/log-rust \
	trusty/user/base/lib/trusty-std \

MODULE_BINDGEN_SRC_HEADER := $(LOCAL_DIR)/bindings.h

MODULE_INCLUDES += \
	$(LOCAL_DIR)/../include/lib/storage \
	trusty/user/base/interface/storage/include \

MODULE_BINDGEN_ALLOW_VARS := \
	STORAGE_.* \

MODULE_BINDGEN_ALLOW_FUNCTIONS := \
	storage_.* \

MODULE_BINDGEN_ALLOW_TYPES := \
	storage_.* \

MODULE_RUST_TESTS := true

# For test service
MANIFEST := $(LOCAL_DIR)/manifest.json

include make/library.mk
