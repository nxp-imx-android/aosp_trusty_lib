/*
 * Copyright 2021, The Android Open Source Project
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

#define TLOG_TAG "acvp"

#include "modulewrapper.h"

#include <string>
#include <vector>

#include <assert.h>
#include <interface/acvp/acvp.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <openssl/span.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <trusty_ipc.h>
#include <trusty_log.h>

#define PAGE_SIZE getauxval(AT_PAGESZ)

// Keep modulewrapper.h and acvp.h in sync
static_assert(bssl::acvp::kMaxArgs == ACVP_MAX_NUM_ARGUMENTS);
static_assert(bssl::acvp::kMaxNameLength == ACVP_MAX_NAME_LENGTH);

static struct tipc_port_acl kAcvpPortAcl = {
        .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
        .uuid_num = 0,
        .uuids = NULL,
        .extra_data = NULL,
};

static struct tipc_port kAcvpPort = {
        .name = ACVP_PORT,
        .msg_max_size = ACVP_MAX_MESSAGE_LENGTH,
        .msg_queue_len = 1,
        .acl = &kAcvpPortAcl,
        .priv = NULL,
};

static inline size_t AlignUpToPage(size_t size) {
    return (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

class TrustyAcvpTool {
public:
    TrustyAcvpTool(handle_t chan) : chan_(chan) {}

    // Send a reply back to the acvptool.
    //
    // This function is used by the handler functions to write out results and
    // should be customized by the tool implementation.
    bool WriteReply(std::vector<bssl::Span<const uint8_t>> spans);

    bool MapShm(handle_t handle, size_t shm_size);

    const uint8_t* arg_buffer() const {
        assert(arg_buffer_);
        return arg_buffer_;
    }

    ~TrustyAcvpTool();

private:
    // Communication handle with the Android modulewrapper tool
    handle_t chan_;

    // Handle to the shared memory region for arguments
    handle_t shm_handle_;

    // Size of arg_buffer_ (must be page-aligned)
    size_t arg_buffer_size_;

    // Mapped buffer from shm_handle_
    uint8_t* arg_buffer_;
};

bool TrustyAcvpTool::WriteReply(std::vector<bssl::Span<const uint8_t>> spans) {
    if (spans.empty() || spans.size() > bssl::acvp::kMaxArgs) {
        abort();
    }

    struct acvp_resp resp;
    resp.num_spans = spans.size();
    uint8_t* cur_buffer = arg_buffer_;
    for (size_t i = 0; i < spans.size(); i++) {
        const auto& span = spans[i];
        resp.lengths[i] = span.size();
        if (span.empty()) {
            continue;
        }

        assert(span.size() < arg_buffer_size_ &&
               cur_buffer - arg_buffer_ + span.size() <= arg_buffer_size_);
        memcpy(cur_buffer, span.data(), span.size());
        cur_buffer += span.size();
    }

    int rc = tipc_send1(chan_, &resp, sizeof(struct acvp_resp));
    if (rc != sizeof(struct acvp_resp)) {
        TLOGE("Failed to send ACVP response\n");
        return false;
    }

    return true;
}

bool TrustyAcvpTool::MapShm(handle_t shm, size_t size) {
    arg_buffer_size_ = AlignUpToPage(size);
    shm_handle_ = shm;
    arg_buffer_ = (uint8_t*)mmap(NULL, arg_buffer_size_, PROT_READ | PROT_WRITE,
                                 0, shm_handle_, 0);
    if (!arg_buffer_) {
        return false;
    }

    return true;
}

TrustyAcvpTool::~TrustyAcvpTool() {
    if (arg_buffer_) {
        munmap((void*)arg_buffer_, arg_buffer_size_);
    }

    if (shm_handle_ != INVALID_IPC_HANDLE) {
        close(shm_handle_);
    }

    if (chan_ != INVALID_IPC_HANDLE) {
        close(chan_);
    }
}

static int ParseAcvpMessage(handle_t chan,
                            uint8_t buffer[ACVP_MAX_MESSAGE_LENGTH],
                            struct acvp_req** request,
                            handle_t* shared_mem) {
    int rc;
    struct ipc_msg_info msg_info;

    rc = get_msg(chan, &msg_info);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to get_msg()\n", rc);
        return rc;
    }

    struct iovec iov = {
            .iov_base = buffer,
            .iov_len = ACVP_MAX_MESSAGE_LENGTH,
    };
    struct ipc_msg msg = {
            .num_iov = 1,
            .iov = &iov,
            .num_handles = msg_info.num_handles,
            .handles = shared_mem,
    };

    if (msg_info.len < sizeof(struct acvp_req)) {
        TLOGE("Message is too short: %zd\n", msg_info.len);
        rc = ERR_BAD_LEN;
        goto err;
    }

    if (msg_info.num_handles > 1) {
        TLOGE("Expected 0 or 1 handles, found %d\n", msg_info.num_handles);
        rc = ERR_BAD_LEN;
        goto err;
    }

    rc = read_msg(chan, msg_info.id, 0, &msg);
    if (rc != sizeof(struct acvp_req)) {
        TLOGE("failed (%d) to read_msg()\n", rc);
        if (rc >= 0) {
            rc = ERR_BAD_LEN;
        }
        goto err;
    }

    rc = NO_ERROR;

    *request = (struct acvp_req*)buffer;

err:
    put_msg(chan, msg_info.id);
    return rc;
}

static int AcvpOnConnect(const struct tipc_port* port,
                         handle_t chan,
                         const struct uuid* peer,
                         void** ctx_p) {
    TrustyAcvpTool* tool = new TrustyAcvpTool(chan);
    *ctx_p = reinterpret_cast<void*>(tool);
    return NO_ERROR;
}

static int AcvpOnMessage(const struct tipc_port* port,
                         handle_t chan,
                         void* ctx) {
    assert(port == &kAcvpPort);
    assert(ctx != nullptr);

    TrustyAcvpTool* tool = reinterpret_cast<TrustyAcvpTool*>(ctx);

    uint8_t message_buffer[ACVP_MAX_MESSAGE_LENGTH];
    struct acvp_req* request = nullptr;
    handle_t shared_mem;
    int rc = ParseAcvpMessage(chan, message_buffer, &request, &shared_mem);
    if (rc != NO_ERROR) {
        TLOGE("Could not parse ACVP message: %d\n", rc);
        return rc;
    }

    if (request->num_args > bssl::acvp::kMaxArgs) {
        TLOGE("Too many args in ACVP message: %d\n", request->num_args);
        return ERR_INVALID_ARGS;
    }

    bssl::Span<const uint8_t> args[bssl::acvp::kMaxArgs];
    if (!tool->MapShm(shared_mem, request->buffer_size)) {
        return ERR_NO_MEMORY;
    }

    uint32_t cur_offset = 0;
    for (uint32_t i = 0; i < request->num_args; ++i) {
        args[i] = bssl::Span<const uint8_t>(tool->arg_buffer() + cur_offset,
                                            request->lengths[i]);
        cur_offset += request->lengths[i];
    }

    auto handler = bssl::acvp::FindHandler(bssl::Span(args, request->num_args));
    if (!handler) {
        const std::string name(reinterpret_cast<const char*>(args[0].data()),
                               args[0].size());
        TLOGE("Unknown operation: %s\n", name.c_str());
        return ERR_NOT_FOUND;
    }

    bssl::acvp::ReplyCallback callback = [tool](auto spans) {
        return tool->WriteReply(spans);
    };

    if (!handler(&args[1], callback)) {
        const std::string name(reinterpret_cast<const char*>(args[0].data()),
                               args[0].size());
        TLOGE("\'%s\' operation failed.\n", name.c_str());
        return ERR_GENERIC;
    }

    return NO_ERROR;
}

static void AcvpOnChannelCleanup(void* ctx) {
    TrustyAcvpTool* tool = reinterpret_cast<TrustyAcvpTool*>(ctx);
    delete tool;
}

static struct tipc_srv_ops kAcvpOps = {
        .on_connect = AcvpOnConnect,
        .on_message = AcvpOnMessage,
        .on_channel_cleanup = AcvpOnChannelCleanup,
};

int main(void) {
    struct tipc_hset* hset = tipc_hset_create();

    if (IS_ERR(hset)) {
        return PTR_ERR(hset);
    }

    int rc = tipc_add_service(hset, &kAcvpPort, 1, 1, &kAcvpOps);
    if (rc < 0) {
        return rc;
    }

    rc = tipc_run_event_loop(hset);
    return rc;
}