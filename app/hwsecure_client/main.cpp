/*
 * Copyright 2022 NXP.
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

#define TLOG_TAG "hwsecure_client"

#include <lib/keymaster/keymaster.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <sys/mman.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include "hwsecure_client_ipc.h"

struct chan_ctx {
    bool inited;
};

static int hwsecure_client_recv(handle_t chan,
                               hwsecure_client_req* req) {
    int rc;
    ipc_msg_info msg_info;
    struct iovec iov = {
            .iov_base = req,
            .iov_len = sizeof(*req),
    };
    struct ipc_msg ipc_msg = {
            .num_iov = 1,
            .iov = &iov,
    };

    rc = get_msg(chan, &msg_info);
    if (rc != NO_ERROR) {
         TLOGE("Failed to get message (%d)\n", rc);
         return rc;
    }

    if (msg_info.len > sizeof(*req)) {
        TLOGE("Message is too long (%zd)\n", msg_info.len);
        rc = ERR_BAD_LEN;
        goto out;
    }

    rc = read_msg(chan, msg_info.id, 0, &ipc_msg);

 out:
     put_msg(chan, msg_info.id);
     return rc;
 }

static int on_connect(const struct tipc_port* port,
                      handle_t chan,
                      const struct uuid* peer,
                      void** ctx_p) {

    struct chan_ctx* ctx = (struct chan_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        TLOGE("Failed to allocate channel context\n");
        return ERR_NO_MEMORY;
    }
    ctx->inited = true;
    *ctx_p = ctx;
    return NO_ERROR;
}

static int handle_msg(handle_t chan, hwsecure_client_req* req, struct chan_ctx* ctx) {
    int rc = 0;
    struct hwsecure_client_resp resp;
    memset(&resp, 0, sizeof(struct hwsecure_client_resp));
    if (!ctx->inited) {
        TLOGE("TA is not initialized.\n");
        return ERR_BAD_STATE;
    }

    switch (req->cmd) {
       case ENABLE_G2D_SECURE_MODE:
           rc = set_widevine_g2d_secure_mode(true);
           break;
       case DISABLE_G2D_SECURE_MODE:
           rc = set_widevine_g2d_secure_mode(false);
           break;
       case GET_G2D_SECURE_MODE:
           rc = get_widevine_g2d_secure_mode((int*)(&resp.mode.g2d_secure_mode));
           break;
       case SECURE_IME_ENABLE_SECURE_POLICY:
           rc = set_ime_secure_access(true);
           break;
       case SECURE_IME_DISABLE_SECURE_POLICY:
           rc = set_ime_secure_access(false);
           break;
       case SECURE_IME_GET_SECURE_MODE:
           rc = get_ime_secure_mode((int*)(&resp.mode.secureime_secure_mode));
           break;
       default:
           TLOGE("no known command\n");
           rc = -1;
           break;
    }
    resp.cmd = req->cmd | HWSECURE_CLIENT_RESP_BIT;
    resp.result = rc;
    rc = tipc_send1(chan, &resp, sizeof(resp));
    if (rc != (int)(sizeof(resp))) {
        TLOGE("Failed to send response (%d)\n", rc);
        if (rc >= 0) {
            rc = ERR_BAD_LEN;
        }
        return rc;
    }
    return NO_ERROR;
}


static int on_message(const struct tipc_port* port, handle_t chan, void* _ctx) {
    int rc;
    struct hwsecure_client_req req;
    struct chan_ctx* ctx = (struct chan_ctx*)_ctx;

    assert(ctx);

    rc = hwsecure_client_recv(chan, &req);
    if (rc < 0) {
        TLOGE("Failed to receive hwsecure_client request (%d)\n", rc);
        return rc;
    }

    if (rc != (int)sizeof(req)) {
        TLOGE("Receive request of unexpected size(%d)\n", rc);
        rc = ERR_BAD_LEN;
        return rc;
    }

    rc = handle_msg(chan, &req, ctx);

    return rc;
}

static void on_channel_cleanup(void* _ctx) {
    struct chan_ctx* ctx = (struct chan_ctx*)_ctx;
    free(ctx);
}

static struct tipc_port_acl hwsecure_client_port_acl = {
        .flags = IPC_PORT_ALLOW_NS_CONNECT,
};

static struct tipc_port hwsecure_client_port = {
        .name = HWSECURE_CLIENT_PORT,
        .msg_max_size = 1024,
        .msg_queue_len = 1,
        .acl = &hwsecure_client_port_acl,
};

static struct tipc_srv_ops hwsecure_client_ops = {
        .on_connect = on_connect,
        .on_message = on_message,
        .on_channel_cleanup = on_channel_cleanup,
};

int main(void) {
    int rc;
    struct tipc_hset* hset;

    TLOGD("Initializing hwsecure_client app\n");

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return PTR_ERR(hset);
    }

    rc = tipc_add_service(hset, &hwsecure_client_port, 1, 1,
                          &hwsecure_client_ops);
    if (rc != NO_ERROR) {
        return rc;
    }

    return tipc_run_event_loop(hset);
}
