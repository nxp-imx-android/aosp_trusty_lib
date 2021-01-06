# Copyright (C) 2019 The Android Open Source Project
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

include trusty/user/app/keymaster/usertests-inc.mk
include trusty/user/app/sample/usertests-inc.mk
include trusty/user/app/storage/usertests-inc.mk

TRUSTY_ALL_USER_TASKS += \
	trusty/user/base/app/acvp \
	trusty/user/base/app/apploader/tests \
	trusty/user/base/app/crash-test \
	trusty/user/base/app/crash-test/crasher \
	trusty/user/base/lib/keymaster/test \
	trusty/user/base/lib/libc-trusty/test \
	trusty/user/base/lib/libstdc++-trusty/test \
	trusty/user/base/lib/secure_fb/test \
	trusty/user/base/lib/smc/tests \
	trusty/user/base/lib/tipc/test/main \
	trusty/user/base/lib/tipc/test/srv \
	trusty/user/base/lib/uirq/test \

ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
TRUSTY_ALL_USER_TASKS += \
	trusty/user/base/lib/sancov/test/srv \

endif

ifeq (true,$(call TOBOOL,$(USER_HWASAN_ENABLED)))
TRUSTY_ALL_USER_TASKS += \
	trusty/user/base/lib/hwasan/test \

endif
