/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <lk/compiler.h>
#include <stdint.h>

__BEGIN_CDECLS

typedef enum trusty_secure_fb_error_e {
    TTUI_ERROR_OK = 0,
    TTUI_ERROR_NO_FRAMEBUFFER,
    TTUI_ERROR_MEMORY_ALLOCATION_FAILED,
    TTUI_ERROR_UNEXPECTED_NULL_PTR,
    TTUI_ERROR_BUFFER_SIZE_MISSMATCH,
} trusty_secure_fb_error;

typedef enum trusty_secure_fb_pixel_format_e {
    TTUI_PF_INVALID = 0,
    /*
     * only supported pixel format with 8 bits per channel such that
     * a pixel can be represented as uint32_t 0xAABBGGRR with
     * AA - Alpha channel
     * BB - Blue channel
     * GG - Green channel
     * RR - Red channel
     */
    TTUI_PF_RGBA8 = 1,
} trusty_secure_fb_pixel_format;

struct trusty_secure_fb_info {
    uint8_t* buffer;        // pointer to the beginning of the framebuffer
    uint32_t size;          // size of buffer in bytes
    uint32_t pixel_stride;  // offset from one pixel to the next in bytes
    uint32_t line_stride;   // offset from one line to the next in bytes
    uint32_t width;         // width of framebuffer in pixels
    uint32_t height;        // height of framebuffer in pixels
    trusty_secure_fb_pixel_format pixel_format;  // should be TTUI_PF_RGBA8
};

/*
 * If returns TUI_ERROR_OK the given teeui_fb struct is filled with valid
 * framebuffer information. Valid means:
 * * fb_info->buffer points to a writable region of memory of at least
 *   fb_info->size bytes length.
 * * fb_info->pixel_stride is greater or equal to the required width for the
 *   pixel format indicated in fb_info->pixel_format.
 * * fb_info->width * fb_info->pixel_stride <= fb_info->line_stride.
 * * fb_info->height * fb_info->line_stride <= fb_info->size.
 *
 * Above this, the frame buffer dimensions must be such that the frame buffer
 * fills the whole primary device screen.
 *
 * @fb_info: output parameter that hold the frame buffer description of the
 *         next frambuffer that will be displayed on the next call to
 *         trusty_secure_fb_display_next.
 *
 * Return:
 * TTUI_ERROR_OK - on success.
 * TTUI_ERROR_NO_FRAMEBUFFER - if for whatever reason no next framebuffer could
 *         be found.
 * TTUI_ERROR_MEMORY_ALLOCATION_FAILED - if any memory allocation failed during
 *         the operation.
 * TTUI_ERROR_UNEXPECTED_NULL_PTR - if the fb_info parameter was NULL.
 */
trusty_secure_fb_error trusty_secure_fb_get_secure_fb(
        struct trusty_secure_fb_info* fb_info);

/*
 * Indicates to the subsystem that the next buffer is ready to be displayed. The
 * next buffer is always the last buffer returned by getSecureFB or displayNext.
 * The content of the structure pointed to by fb_info is ignored and replaced
 * with a new off-screen framebuffer, that the caller can use to render the next
 * frame. The copy parameter indicates that the caller wants the subsystem to
 * copy the content of the current buffer into the new buffer. This could be
 * used to leverage hw support for blitting framebuffers if such exist. If
 * return TUI_ERROR_OK:
 * * The last buffer returned by getSecureFB or displayNext gets displayed.
 * * The first call to displayNext starts the TUI session, i.e. the secure
 *   output path is configured and verified:
 * * The power supply to the display panel and controller gets sanitized and
 *   locked.
 * * The display controller's secure resources get locked and configured for
 *   secure output.
 * * The display controller's state gets sanitized.
 * * The framebuffer gets configured as the secure scanout region.
 *
 * @fb_info: output parameter that holds the frame buffer description for the
 *         next frame buffer.
 * @copy:  Indicates if the new framebuffer should be initialized with a copy of
 *         of the previous buffer. This allow hardware optimization in case the
 *         hardware supports accelerated blitting or similar.
 *
 * Return:
 * TTUI_ERROR_OK - on success.
 * TTUI_ERROR_NO_FRAMEBUFFER - if for whatever reason no next framebuffer could
 *         be found.
 * TTUI_ERROR_MEMORY_ALLOCATION_FAILED - if any memory allocation failed during
 *         the operation.
 * TTUI_ERROR_UNEXPECTED_NULL_PTR - if the fb_info parameter was NULL.
 * TTUI_ERROR_BUFFER_SIZE_MISSMATCH - if copy was requested but subsequent
 * buffers have different size.
 */
trusty_secure_fb_error trusty_secure_fb_display_next(
        struct trusty_secure_fb_info* fb_info,
        int copy);

/*
 * Wipe the secure frame buffers.
 * Relinquishes control over secure display resources.
 * If releaseDisplay encounters any irregularity it does not return but causes
 * the SOC to reset.
 */
void trusty_secure_fb_release_display(void);

__END_CDECLS
