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

#include <interface/secure_fb/secure_fb.h>

#include <stdlib.h>  // for NULL

/*
 * Pseudo framebuffer initialized to Pixel 3 (blueline) dimensions.
 */
static struct trusty_secure_fb_info s_fb_info = {.buffer = NULL,
                                                 .size = 1080 * 2160 * 4,
                                                 .pixel_stride = 4,
                                                 .line_stride = 1080 * 4,
                                                 .width = 1080,
                                                 .height = 2160,
                                                 .pixel_format = TTUI_PF_RGBA8};

trusty_secure_fb_error trusty_secure_fb_get_secure_fb(
        struct trusty_secure_fb_info* fb_info) {
    if (fb_info == NULL)
        return TTUI_ERROR_UNEXPECTED_NULL_PTR;
    if (s_fb_info.buffer == NULL) {
        s_fb_info.buffer = malloc(s_fb_info.size);
        if (s_fb_info.buffer == NULL) {
            return TTUI_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }
    *fb_info = s_fb_info;
    return TTUI_ERROR_OK;
}

trusty_secure_fb_error trusty_secure_fb_display_next(
        struct trusty_secure_fb_info* fb_info,
        int copy) {
    if (fb_info == NULL)
        return TTUI_ERROR_UNEXPECTED_NULL_PTR;
    if (s_fb_info.buffer == NULL)
        return TTUI_ERROR_NO_FRAMEBUFFER;
    (void)copy;
    /*
     * We just return the same buffer again. This is just a dummy anyway.
     */
    *fb_info = s_fb_info;
    return TTUI_ERROR_OK;
}

void trusty_secure_fb_release_display() {
    free(s_fb_info.buffer);
    s_fb_info.buffer = NULL;
}
