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

MODULE_SRCS := external/rust/crates/syn/src/lib.rs

MODULE_CRATE_NAME := syn

MODULE_RUST_EDITION := 2018

MODULE_RUSTFLAGS += \
	--cfg 'feature="clone-impls"' \
	--cfg 'feature="default"' \
	--cfg 'feature="derive"' \
	--cfg 'feature="extra-traits"' \
	--cfg 'feature="full"' \
	--cfg 'feature="parsing"' \
	--cfg 'feature="printing"' \
	--cfg 'feature="proc-macro"' \
	--cfg 'feature="quote"' \
	--cfg 'feature="visit"' \
	--cfg 'feature="visit-mut"' \

MODULE_LIBRARY_DEPS := \
	trusty/user/base/host/proc-macro2 \
	trusty/user/base/host/quote \
	trusty/user/base/host/unicode-xid \

include make/library.mk
