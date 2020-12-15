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

#define TLOG_TAG "secure_fb_service"

#include <assert.h>
#include <interface/secure_fb/secure_fb.h>
#include <lib/secure_fb/srv/dev.h>
#include <lib/secure_fb/srv/srv.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/compiler.h>
#include <lk/macros.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <uapi/err.h>

struct secure_fb_ctx {
    secure_fb_handle_t session;
};

static int secure_fb_on_connect(const struct tipc_port* port,
                                handle_t chan,
                                const struct uuid* peer,
                                void** ctx_p) {
    struct secure_fb_ctx* ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        TLOGE("Memory allocation failed.\n");
        return ERR_NO_MEMORY;
    }

    ctx->session = secure_fb_impl_init();
    if (ctx->session == NULL) {
        TLOGE("Driver initialization failed.\n");
        free(ctx);
        return ERR_GENERIC;
    }

    *ctx_p = ctx;
    return NO_ERROR;
}

static void secure_fb_on_channel_cleanup(void* _ctx) {
    struct secure_fb_ctx* ctx = (struct secure_fb_ctx*)_ctx;
    if (ctx->session != NULL) {
        secure_fb_impl_release(ctx);
    }
    free(ctx);
}

static int handle_get_fbs_req(handle_t chan, secure_fb_handle_t session) {
    int rc;
    struct secure_fb_impl_buffers buffers;
    struct secure_fb_resp hdr;
    struct secure_fb_get_fbs_resp args;
    struct secure_fb_desc fbs[SECURE_FB_MAX_FBS];
    size_t fbs_len;

    rc = secure_fb_impl_get_fbs(session, &buffers);
    if (rc != SECURE_FB_ERROR_OK) {
        TLOGE("Failed secure_fb_impl_get_fbs() (%d)\n", rc);
    }

    hdr.cmd = SECURE_FB_CMD_GET_FBS | SECURE_FB_CMD_RESP_BIT;
    hdr.status = rc;

    args.num_fbs = buffers.num_fbs;

    fbs_len = sizeof(fbs[0]) * args.num_fbs;
    memcpy(fbs, buffers.fbs, fbs_len);

    struct iovec iovs[] = {
            {
                    .iov_base = &hdr,
                    .iov_len = sizeof(hdr),
            },
            {
                    .iov_base = &args,
                    .iov_len = sizeof(args),
            },
            {
                    .iov_base = fbs,
                    .iov_len = fbs_len,
            },
    };
    ipc_msg_t msg = {
            .num_iov = countof(iovs),
            .iov = iovs,
            .num_handles = buffers.num_handles,
            .handles = buffers.handles,
    };
    rc = send_msg(chan, &msg);
    if (rc != (int)(sizeof(hdr) + sizeof(args) + fbs_len)) {
        TLOGE("Failed to send SECURE_FB_CMD_GET_FBS response (%d)\n", rc);
        if (rc >= 0) {
            return ERR_BAD_LEN;
        }
    }

    return NO_ERROR;
}

static int handle_display_fb(handle_t chan,
                             struct secure_fb_display_fb_req* display_fb,
                             secure_fb_handle_t session) {
    int rc;
    struct secure_fb_resp hdr;

    rc = secure_fb_impl_display_fb(session, display_fb->buffer_id);
    if (rc != SECURE_FB_ERROR_OK) {
        TLOGE("Failed secure_fb_impl_display_fb() (%d)\n", rc);
    }

    hdr.cmd = SECURE_FB_CMD_DISPLAY_FB | SECURE_FB_CMD_RESP_BIT;
    hdr.status = rc;

    rc = tipc_send1(chan, &hdr, sizeof(hdr));
    if (rc != (int)sizeof(hdr)) {
        TLOGE("Failed to send SECURE_FB_CMD_DISPLAY_FB response (%d)\n", rc);
        if (rc >= 0) {
            return ERR_BAD_LEN;
        }
    }

    return NO_ERROR;
}

static int secure_fb_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* _ctx) {
    int rc;
    struct {
        struct secure_fb_req hdr;
        union {
            struct secure_fb_display_fb_req display_fb;
        };
    } req;
    struct secure_fb_ctx* ctx = (struct secure_fb_ctx*)_ctx;

    rc = tipc_recv1(chan, sizeof(req.hdr), &req, sizeof(req));
    if (rc < 0) {
        TLOGE("Failed to read command %d\n", rc);
        return ERR_BAD_LEN;
    }

    switch (req.hdr.cmd) {
    case SECURE_FB_CMD_GET_FBS:
        if (rc != (int)sizeof(req.hdr)) {
            TLOGE("Failed to read SECURE_FB_CMD_GET_FBS request (%d)\n", rc);
            return ERR_BAD_LEN;
        }
        return handle_get_fbs_req(chan, ctx->session);

    case SECURE_FB_CMD_DISPLAY_FB:
        if (rc != (int)(sizeof(req.hdr) + sizeof(req.display_fb))) {
            TLOGE("Failed to read SECURE_FB_CMD_DISPLAY_FB request (%d)\n", rc);
            return ERR_BAD_LEN;
        }
        return handle_display_fb(chan, &req.display_fb, ctx->session);

    case SECURE_FB_CMD_RELEASE:
        if (rc != (int)sizeof(req.hdr)) {
            TLOGE("Failed to read SECURE_FB_CMD_RELEASE request (%d)\n", rc);
            return ERR_BAD_LEN;
        }
        secure_fb_impl_release(ctx->session);
        ctx->session = NULL;
        return NO_ERROR;

    default:
        TLOGW("Received unknown command %x\n", req.hdr.cmd);
        return ERR_CMD_UNKNOWN;
    }

    return NO_ERROR;
}

int add_secure_fb_service(struct tipc_hset* hset) {
    static struct tipc_port_acl acl = {
            .flags = IPC_PORT_ALLOW_TA_CONNECT,
    };
    static struct tipc_port port = {
            .name = SECURE_FB_PORT_NAME,
            .msg_max_size = 1024,
            .msg_queue_len = 1,
            .acl = &acl,
    };
    static struct tipc_srv_ops ops = {
            .on_connect = secure_fb_on_connect,
            .on_message = secure_fb_on_message,
            .on_channel_cleanup = secure_fb_on_channel_cleanup,
    };

    /*
     * The secure display is a limited resource. This means only one client
     * can have an open session at a time.
     */
    return tipc_add_service(hset, &port, 1, 1, &ops);
}
