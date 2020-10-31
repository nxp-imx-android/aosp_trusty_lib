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

#define TLOG_TAG "sancov-rt"

#include <assert.h>
#include <interface/coverage/aggregator.h>
#include <lib/coverage/common/ipc.h>
#include <lib/coverage/common/shm.h>
#include <lib/tipc/tipc.h>
#include <lk/macros.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <trusty_log.h>
#include <uapi/err.h>

#define PAGE_SIZE getauxval(AT_PAGESZ)

typedef uint8_t counter_t;

struct sancov_ctx {
    handle_t coverage_srv;
    size_t idx;
    struct shm mailbox;
    struct shm data;
    size_t record_len;
};

static bool in_sancov = false;

#define SANCOV_START \
    if (in_sancov) { \
        return;      \
    }                \
    in_sancov = true;

#define SANCOV_FINISH in_sancov = false;

static int init(struct sancov_ctx* ctx, size_t record_len) {
    int rc;
    handle_t chan;
    handle_t memref;
    struct coverage_aggregator_req req;
    struct coverage_aggregator_resp resp;

    rc = tipc_connect(&chan, COVERAGE_AGGREGATOR_PORT);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to connect to coverage aggregator service\n", rc);
        return rc;
    }

    req.hdr.cmd = COVERAGE_AGGREGATOR_CMD_REGISTER;
    req.register_args.record_len = record_len;

    rc = coverage_aggregator_rpc(chan, &req, NULL, &resp, &memref);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) coverage aggregator RPC\n", rc);
        goto err_rpc;
    }

    rc = shm_mmap(&ctx->mailbox, memref, resp.register_args.mailbox_len);
    if (rc != NO_ERROR) {
        TLOGE("failed to mmap() mailbox shared memory\n");
        goto err_mmap;
    }

    ctx->coverage_srv = chan;
    ctx->idx = resp.register_args.idx;
    ctx->record_len = record_len;

    close(memref);
    return NO_ERROR;

err_mmap:
    close(memref);
err_rpc:
    close(chan);
    return rc;
}

static int get_record(struct sancov_ctx* ctx) {
    int rc;
    handle_t memref;
    struct coverage_aggregator_req req;
    struct coverage_aggregator_resp resp;
    size_t shm_len;

    req.hdr.cmd = COVERAGE_AGGREGATOR_CMD_GET_RECORD;

    rc = coverage_aggregator_rpc(ctx->coverage_srv, &req, NULL, &resp, &memref);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) coverage aggregator RPC\n", rc);
        return rc;
    }
    shm_len = resp.get_record_args.shm_len;

    if (shm_len < ctx->record_len) {
        TLOGE("not enough shared memory, received: %zu, need at least: %zu\n",
              shm_len, ctx->record_len);
        rc = ERR_BAD_LEN;
        goto out;
    }

    rc = shm_mmap(&ctx->data, memref, resp.get_record_args.shm_len);
    if (rc != NO_ERROR) {
        TLOGE("failed to mmap() coverage record shared memory\n");
        goto out;
    }

    rc = NO_ERROR;

out:
    close(memref);
    return rc;
}

static void update_record(struct sancov_ctx* ctx, size_t idx) {
    volatile counter_t* counters = ctx->data.base;
    counters[idx]++;
}

static int get_event(struct sancov_ctx* ctx) {
    int* app_mailbox = (int*)(ctx->mailbox.base) + ctx->idx;
    int event = READ_ONCE(*app_mailbox);
    WRITE_ONCE(*app_mailbox, COVERAGE_MAILBOX_EMPTY);
    return event;
};

static struct sancov_ctx ctx;

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    SANCOV_START;

    static size_t num_counters = 0;
    int rc;

    /* Initialize only once */
    if (start == stop || *start) {
        goto out;
    }

    for (uint32_t* x = start; x < stop; x++) {
        *x = ++num_counters;
    }

    TLOGI("sancov initialized with %lu counters\n", num_counters);

    rc = init(&ctx, num_counters * sizeof(counter_t));
    assert(rc == NO_ERROR);

out:
    SANCOV_FINISH;
}

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
    SANCOV_START;

    int rc;
    int event = get_event(&ctx);

    /* Guards start at 1, and indices start at 0 */
    assert(*guard > 0);
    size_t idx = *guard - 1;

    switch (event) {
    case COVERAGE_MAILBOX_EMPTY:
        break;

    case COVERAGE_MAILBOX_RECORD_READY:
        if (shm_is_mapped(&ctx.data)) {
            shm_munmap(&ctx.data);
        }

        rc = get_record(&ctx);
        assert(rc == NO_ERROR);
        break;

    default:
        TLOGE("unknown event: %d\n", event);
        abort();
    }

    if (shm_is_mapped(&ctx.data)) {
        update_record(&ctx, idx);
    }

    SANCOV_FINISH;
}
