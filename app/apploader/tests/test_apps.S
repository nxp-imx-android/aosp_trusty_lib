/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


.section .data

.global version_test_app_v1_start, version_test_app_v1_end
.hidden version_test_app_v1_start, version_test_app_v1_end
.balign 4096
version_test_app_v1_start:
.incbin VERSION_TEST_APP_V1
version_test_app_v1_end:

.global version_test_app_v2_start, version_test_app_v2_end
.hidden version_test_app_v2_start, version_test_app_v2_end
.balign 4096
version_test_app_v2_start:
.incbin VERSION_TEST_APP_V2
version_test_app_v2_end:
