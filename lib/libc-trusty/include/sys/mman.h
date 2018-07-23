/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <lk/compiler.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <uapi/mm.h>

__BEGIN_CDECLS

#define MAP_FAILED ((void *) -1)

#define PROT_NONE      0
#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_EXEC      4

void *mmap(void *uaddr, size_t size, int prot, int flags, int handle, off_t offset);
int munmap(void *uaddr, size_t size);

/* Trusty specific. */
long prepare_dma(void *uaddr, uint32_t size, uint32_t flags,
                 struct dma_pmem *pmem);
long finish_dma(void *uaddr, uint32_t size, uint32_t flags);

__END_CDECLS
