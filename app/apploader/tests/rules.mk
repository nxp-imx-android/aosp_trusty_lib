# Copyright (C) 2020 The Android Open Source Project
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

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/apploader_test.c \
	$(LOCAL_DIR)/test_apps.S \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/tipc \
	trusty/user/base/lib/unittest \
	trusty/user/base/interface/apploader \

VERSION_TEST_APP_V1 := \
	$(abspath $(TRUSTY_APP_BUILDDIR)/trusty/user/base/app/apploader/tests/version_test_apps/v1/v1.app)
VERSION_TEST_APP_V2 := \
	$(abspath $(TRUSTY_APP_BUILDDIR)/trusty/user/base/app/apploader/tests/version_test_apps/v2/v2.app)

MODULE_ASMFLAGS += \
       -DVERSION_TEST_APP_V1=\"$(VERSION_TEST_APP_V1)\" \
       -DVERSION_TEST_APP_V2=\"$(VERSION_TEST_APP_V2)\" \

MODULE_SRCDEPS += \
       $(VERSION_TEST_APP_V1) \
       $(VERSION_TEST_APP_V2) \

include make/trusted_app.mk
