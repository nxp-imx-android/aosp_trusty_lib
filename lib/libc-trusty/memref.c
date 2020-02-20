#include <stddef.h>
#include <stdint.h>
#include <trusty_err.h>
#include <trusty_syscalls.h>

int memref_create(void* addr, size_t size, uint32_t mmap_prot) {
    /* Check size fits in a uint32_t until size_t in syscalls is supported */
    if (size > UINT32_MAX) {
        return -ERR_INVALID_ARGS;
    }
    return _trusty_memref_create(addr, size, mmap_prot);
}
