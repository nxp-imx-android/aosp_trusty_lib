/*
 * Copyright (c) 2012-2018 LK Trusty Authors. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* This file is auto-generated. !!! DO NOT EDIT !!! */

#include <trusty_syscalls.h>

.section .text._trusty_write
.global _trusty_write
.type _trusty_write,STT_FUNC
_trusty_write:
    ldr     r12, =__NR_write
    swi     #0
    bx      lr

.section .text._trusty_brk
.global _trusty_brk
.type _trusty_brk,STT_FUNC
_trusty_brk:
    ldr     r12, =__NR_brk
    swi     #0
    bx      lr

.section .text._trusty_exit_etc
.global _trusty_exit_etc
.type _trusty_exit_etc,STT_FUNC
_trusty_exit_etc:
    ldr     r12, =__NR_exit_etc
    swi     #0
    bx      lr

.section .text._trusty_read
.global _trusty_read
.type _trusty_read,STT_FUNC
_trusty_read:
    ldr     r12, =__NR_read
    swi     #0
    bx      lr

.section .text._trusty_ioctl
.global _trusty_ioctl
.type _trusty_ioctl,STT_FUNC
_trusty_ioctl:
    ldr     r12, =__NR_ioctl
    swi     #0
    bx      lr

.section .text._trusty_nanosleep
.global _trusty_nanosleep
.type _trusty_nanosleep,STT_FUNC
_trusty_nanosleep:
    ldr     r12, =__NR_nanosleep
    swi     #0
    bx      lr

.section .text._trusty_gettime
.global _trusty_gettime
.type _trusty_gettime,STT_FUNC
_trusty_gettime:
    ldr     r12, =__NR_gettime
    swi     #0
    bx      lr

.section .text._trusty_mmap
.global _trusty_mmap
.type _trusty_mmap,STT_FUNC
_trusty_mmap:
    ldr     r12, =__NR_mmap
    swi     #0
    bx      lr

.section .text._trusty_munmap
.global _trusty_munmap
.type _trusty_munmap,STT_FUNC
_trusty_munmap:
    ldr     r12, =__NR_munmap
    swi     #0
    bx      lr

.section .text._trusty_prepare_dma
.global _trusty_prepare_dma
.type _trusty_prepare_dma,STT_FUNC
_trusty_prepare_dma:
    ldr     r12, =__NR_prepare_dma
    swi     #0
    bx      lr

.section .text._trusty_finish_dma
.global _trusty_finish_dma
.type _trusty_finish_dma,STT_FUNC
_trusty_finish_dma:
    ldr     r12, =__NR_finish_dma
    swi     #0
    bx      lr

.section .text._trusty_port_create
.global _trusty_port_create
.type _trusty_port_create,STT_FUNC
_trusty_port_create:
    ldr     r12, =__NR_port_create
    swi     #0
    bx      lr

.section .text._trusty_connect
.global _trusty_connect
.type _trusty_connect,STT_FUNC
_trusty_connect:
    ldr     r12, =__NR_connect
    swi     #0
    bx      lr

.section .text._trusty_accept
.global _trusty_accept
.type _trusty_accept,STT_FUNC
_trusty_accept:
    ldr     r12, =__NR_accept
    swi     #0
    bx      lr

.section .text._trusty_close
.global _trusty_close
.type _trusty_close,STT_FUNC
_trusty_close:
    ldr     r12, =__NR_close
    swi     #0
    bx      lr

.section .text._trusty_set_cookie
.global _trusty_set_cookie
.type _trusty_set_cookie,STT_FUNC
_trusty_set_cookie:
    ldr     r12, =__NR_set_cookie
    swi     #0
    bx      lr

.section .text._trusty_handle_set_create
.global _trusty_handle_set_create
.type _trusty_handle_set_create,STT_FUNC
_trusty_handle_set_create:
    ldr     r12, =__NR_handle_set_create
    swi     #0
    bx      lr

.section .text._trusty_handle_set_ctrl
.global _trusty_handle_set_ctrl
.type _trusty_handle_set_ctrl,STT_FUNC
_trusty_handle_set_ctrl:
    ldr     r12, =__NR_handle_set_ctrl
    swi     #0
    bx      lr

.section .text._trusty_wait
.global _trusty_wait
.type _trusty_wait,STT_FUNC
_trusty_wait:
    ldr     r12, =__NR_wait
    swi     #0
    bx      lr

.section .text._trusty_wait_any
.global _trusty_wait_any
.type _trusty_wait_any,STT_FUNC
_trusty_wait_any:
    ldr     r12, =__NR_wait_any
    swi     #0
    bx      lr

.section .text._trusty_get_msg
.global _trusty_get_msg
.type _trusty_get_msg,STT_FUNC
_trusty_get_msg:
    ldr     r12, =__NR_get_msg
    swi     #0
    bx      lr

.section .text._trusty_read_msg
.global _trusty_read_msg
.type _trusty_read_msg,STT_FUNC
_trusty_read_msg:
    ldr     r12, =__NR_read_msg
    swi     #0
    bx      lr

.section .text._trusty_put_msg
.global _trusty_put_msg
.type _trusty_put_msg,STT_FUNC
_trusty_put_msg:
    ldr     r12, =__NR_put_msg
    swi     #0
    bx      lr

.section .text._trusty_send_msg
.global _trusty_send_msg
.type _trusty_send_msg,STT_FUNC
_trusty_send_msg:
    ldr     r12, =__NR_send_msg
    swi     #0
    bx      lr
