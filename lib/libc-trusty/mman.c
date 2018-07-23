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

#include <sys/mman.h>

#include <stddef.h>
#include <stdint.h>
#include <lk/err_ptr.h>
#include <trusty_syscalls.h>

void *mmap(void *uaddr, size_t size, int prot, int flags, int handle,
           off_t offset)
{
    void *result;

    /*
     * These parameters exist for POSIX compatibility, but are unused.
     * Require fixed values.
     */
    if (prot != (PROT_READ | PROT_WRITE)) {
        return MAP_FAILED;
    }
    if (offset != 0) {
        return MAP_FAILED;
    }

    result = (void *)_trusty_mmap(uaddr, size, (uint32_t)flags,
                                  (uint32_t)handle);
    if (IS_ERR(result)) {
        return MAP_FAILED;
    }
    return result;
}

int munmap(void *uaddr, size_t size)
{
    return _trusty_munmap(uaddr, size);
}

long prepare_dma(void *uaddr, uint32_t size, uint32_t flags,
                 struct dma_pmem *pmem)
{
    return _trusty_prepare_dma(uaddr, size, flags, pmem);
}

long finish_dma(void *uaddr, uint32_t size, uint32_t flags)
{
    return _trusty_finish_dma(uaddr, size, flags);
}
