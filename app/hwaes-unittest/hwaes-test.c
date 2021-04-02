/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define TLOG_TAG "hwaes_unittest"

#include <stdlib.h>
#include <string.h>

#include <lib/hwaes/hwaes.h>
#include <memref.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

#define PAGE_SIZE() getauxval(AT_PAGESZ)
#define MAX_TRY_TIMES 1000
#define UNUSED_HWAES_ERROR_CODE HWAES_NO_ERROR

/**
 * struct hwaes_iov - an wrapper of an array of iovec.
 * @iovs: array of iovec.
 * @num_iov: number of iovec.
 * @total_len: total length of the tipc message.
 */
struct hwaes_iov {
    struct iovec iov[TIPC_MAX_MSG_PARTS];
    size_t num_iov;
    size_t total_len;
};

/**
 * struct hwaes_shm - an wrapper of an array of shared memory handles.
 * @handles:     array of shared memory handles.
 * @num_handles: number of shared memory handles.
 */
struct hwaes_shm {
    handle_t handles[HWAES_MAX_NUM_HANDLES];
    size_t num_handles;
};

static const uint8_t hwaes_key[32];
static const uint8_t hwaes_iv[16];
static const uint8_t hwaes_plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t hwaes_ciphertext[] = {
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2,
        0x14, 0x92, 0x84, 0x20, 0x87, 0x08, 0xc3, 0x74, 0x84, 0x8c, 0x22,
        0x82, 0x33, 0xc2, 0xb3, 0x4f, 0x33, 0x2b, 0xd2, 0xe9, 0xd3};

typedef struct hwaes {
    hwaes_session_t hwaes_session;
    handle_t memref;
    void* shm_base;
    size_t shm_len;
    struct hwcrypt_shm_hd shm_hd;
    struct hwcrypt_args args_encrypt;
    struct hwcrypt_args args_decrypt;
    struct hwaes_req req_hdr;
    struct hwaes_aes_req cmd_hdr;
    struct hwaes_shm_desc shm_descs[HWAES_MAX_NUM_HANDLES];
    struct hwaes_iov req_iov;
    struct hwaes_shm req_shm;
} hwaes_t;

static void make_bad_request(handle_t channel,
                             struct hwaes_iov* req_iov,
                             struct hwaes_shm* req_shm,
                             bool expect_reply,
                             uint32_t expect_error) {
    struct uevent event;
    ipc_msg_info_t msg_inf;
    bool got_msg = false;

    ipc_msg_t req_msg = {
            .iov = req_iov->iov,
            .num_iov = req_iov->num_iov,
            .handles = req_shm->handles,
            .num_handles = req_shm->num_handles,
    };

    int rc;
    rc = send_msg(channel, &req_msg);
    ASSERT_EQ((size_t)rc, req_iov->total_len);

    rc = wait(channel, &event, INFINITE_TIME);
    ASSERT_EQ(rc, NO_ERROR);

    if (expect_reply) {
        ASSERT_NE(event.event & IPC_HANDLE_POLL_MSG, 0);
    } else {
        ASSERT_EQ(event.event, IPC_HANDLE_POLL_HUP);
        return;
    }

    rc = get_msg(channel, &msg_inf);
    ASSERT_EQ(rc, NO_ERROR);

    got_msg = true;
    ASSERT_EQ(msg_inf.len, sizeof(struct hwaes_resp));

    struct hwaes_resp resp_hdr = {0};
    struct iovec resp_iov = {
            .iov_base = (void*)&resp_hdr,
            .iov_len = sizeof(resp_hdr),
    };
    ipc_msg_t resp_msg = {
            .iov = &resp_iov,
            .num_iov = 1,
            .handles = NULL,
            .num_handles = 0,
    };
    rc = read_msg(channel, msg_inf.id, 0, &resp_msg);
    ASSERT_EQ((size_t)rc, msg_inf.len);

    struct hwaes_req* req_hdr = (struct hwaes_req*)req_iov->iov[0].iov_base;
    ASSERT_EQ(resp_hdr.cmd, req_hdr->cmd | HWAES_RESP_BIT);

    put_msg(channel, msg_inf.id);
    EXPECT_EQ(expect_error, resp_hdr.result);
    return;

test_abort:
    if (got_msg) {
        put_msg(channel, msg_inf.id);
    }
    return;
}

TEST_F_SETUP(hwaes) {
    int rc;
    void* shm_base;
    size_t shm_len = PAGE_SIZE();
    _state->hwaes_session = INVALID_IPC_HANDLE;
    _state->memref = INVALID_IPC_HANDLE;
    _state->shm_base = NULL;

    rc = hwaes_open(&_state->hwaes_session);
    ASSERT_EQ(rc, 0);

    shm_base = memalign(PAGE_SIZE(), shm_len);
    ASSERT_NE(NULL, shm_base, "fail to allocate shared memory");

    rc = memref_create(shm_base, shm_len, PROT_READ | PROT_WRITE);
    ASSERT_GE(rc, 0);
    _state->memref = (handle_t)rc;
    _state->shm_base = shm_base;
    _state->shm_len = shm_len;
    memset(_state->shm_base, 0, _state->shm_len);
    memcpy(_state->shm_base, hwaes_plaintext, sizeof(hwaes_plaintext));

    _state->shm_hd = (struct hwcrypt_shm_hd){
            .handle = _state->memref,
            .base = _state->shm_base,
            .size = _state->shm_len,
    };

    _state->args_encrypt = (struct hwcrypt_args){
            .key =
                    {
                            .data_ptr = hwaes_key,
                            .len = sizeof(hwaes_key),
                    },
            .iv =
                    {
                            .data_ptr = hwaes_iv,
                            .len = sizeof(hwaes_iv),
                    },
            .text_in =
                    {
                            .data_ptr = _state->shm_base,
                            .len = sizeof(hwaes_plaintext),
                            .shm_hd_ptr = &_state->shm_hd,
                    },
            .text_out =
                    {
                            .data_ptr = _state->shm_base,
                            .len = sizeof(hwaes_ciphertext),
                            .shm_hd_ptr = &_state->shm_hd,
                    },
            .key_type = HWAES_UNWRAPPED_KEY,
            .padding = HWAES_NO_PADDING,
            .mode = HWAES_CBC_MODE,
    };

    _state->args_decrypt = (struct hwcrypt_args){
            .key =
                    {
                            .data_ptr = hwaes_key,
                            .len = sizeof(hwaes_key),
                    },
            .iv =
                    {
                            .data_ptr = hwaes_iv,
                            .len = sizeof(hwaes_iv),
                    },
            .text_in =
                    {
                            .data_ptr = _state->shm_base,
                            .len = sizeof(hwaes_ciphertext),
                            .shm_hd_ptr = &_state->shm_hd,
                    },
            .text_out =
                    {
                            .data_ptr = _state->shm_base,
                            .len = sizeof(hwaes_plaintext),
                            .shm_hd_ptr = &_state->shm_hd,
                    },
            .key_type = HWAES_UNWRAPPED_KEY,
            .padding = HWAES_NO_PADDING,
            .mode = HWAES_CBC_MODE,
    };

    _state->req_hdr = (struct hwaes_req){
            .cmd = HWAES_AES,
    };
    _state->cmd_hdr = (struct hwaes_aes_req){
            .key =
                    (struct hwaes_data_desc){
                            .len = sizeof(hwaes_key),
                            .shm_idx = 0,
                    },
            .num_handles = 1,
    };
    _state->shm_descs[0] = (struct hwaes_shm_desc){.size = _state->shm_len};
    _state->req_iov = (struct hwaes_iov){
            .iov =
                    {
                            {&_state->req_hdr, sizeof(_state->req_hdr)},
                            {&_state->cmd_hdr, sizeof(_state->cmd_hdr)},
                            {&_state->shm_descs, sizeof(struct hwaes_shm_desc)},
                    },
            .num_iov = 3,
            .total_len = sizeof(_state->req_hdr) + sizeof(_state->cmd_hdr) +
                         sizeof(struct hwaes_shm_desc),
    };
    _state->req_shm = (struct hwaes_shm){
            .handles = {_state->memref},
            .num_handles = 1,
    };

test_abort:;
}

TEST_F_TEARDOWN(hwaes) {
    close(_state->hwaes_session);
    close(_state->memref);
    free(_state->shm_base);
}

TEST_F(hwaes, GenericInvalidSession) {
    hwaes_session_t invalid = INVALID_IPC_HANDLE;
    struct hwcrypt_args args = {};

    // should fail immediately
    int rc = hwaes_encrypt(invalid, &args);

    EXPECT_EQ(ERR_BAD_HANDLE, rc, "generic - bad handle");
}

TEST_F(hwaes, RequestHeaderReservedNotZero) {
    _state->req_hdr.reserved = 1U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     false, UNUSED_HWAES_ERROR_CODE);
}

TEST_F(hwaes, CommandUnsupported) {
    _state->req_hdr.cmd = 0U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_NOT_IMPLEMENTED);
}

TEST_F(hwaes, CommandHeaderReservedNotZero) {
    _state->cmd_hdr.reserved = 1U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     false, UNUSED_HWAES_ERROR_CODE);
}

TEST_F(hwaes, SharedMemoryHandlesNumberConflict) {
    _state->cmd_hdr.num_handles += 1;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     false, UNUSED_HWAES_ERROR_CODE);
}

TEST_F(hwaes, SharedMemoryDescriptorReservedNotZero) {
    _state->shm_descs[0].reserved = 1U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_IO);
}

TEST_F(hwaes, SharedMemoryDescriptorWrongWriteFlag) {
    _state->shm_descs[0].write = 2U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_IO);
}

TEST_F(hwaes, SharedMemoryDescriptorBadSize) {
    /* size is not page aligned */
    _state->shm_descs[0].size = 4;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_INVALID_ARGS);
}

TEST_F(hwaes, DataDescriptorReservedNotZero) {
    _state->cmd_hdr.key.reserved = 1U;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_IO);
}

TEST_F(hwaes, DataDescriptorBadLength) {
    _state->cmd_hdr.key.len = _state->shm_len + 1ULL;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_INVALID_ARGS);
}

TEST_F(hwaes, DataDescriptorBadSharedMemoryHandleIndex) {
    _state->cmd_hdr.key.shm_idx = 4;
    make_bad_request(_state->hwaes_session, &_state->req_iov, &_state->req_shm,
                     true, HWAES_ERR_IO);
}
TEST_F(hwaes, InvalidSharedMemoryHandle) {
    struct hwcrypt_shm_hd bad_shm_hd = {
            .handle = INVALID_IPC_HANDLE,
            .base = _state->shm_base,
            .size = _state->shm_len,
    };

    _state->args_encrypt.text_in.shm_hd_ptr = &bad_shm_hd;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_BAD_HANDLE, rc, "expect bad handle error");
}

TEST_F(hwaes, BadSharedMemorySize) {
    struct hwcrypt_shm_hd bad_shm_hd = {
            .handle = _state->memref,
            .base = _state->shm_base,
            .size = 0,
    };

    _state->args_encrypt.text_in.shm_hd_ptr = &bad_shm_hd;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect bad length error");
}

TEST_F(hwaes, KeyArgumentNotSetEncrypt) {
    _state->args_encrypt.key.len = 0;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, IVArgumentNotSetEncrypt) {
    _state->args_encrypt.iv.len = 0;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, TextInArgumentNotSetEncrypt) {
    _state->args_encrypt.text_in.len = 0;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, TextOutArgumentNotSetEncrypt) {
    _state->args_encrypt.text_out.len = 0;

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, KeyArgumentNotSetDecrypt) {
    _state->args_decrypt.key.len = 0;

    int rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, IVArgumentNotSetDecrypt) {
    _state->args_decrypt.iv.len = 0;

    int rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, TextInArgumentNotSetDecrypt) {
    _state->args_decrypt.text_in.len = 0;

    int rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, TextOutArgumentNotSetDecrypt) {
    _state->args_decrypt.text_out.len = 0;

    int rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);
    EXPECT_EQ(ERR_INVALID_ARGS, rc, "expect invalid_args error");
}

TEST_F(hwaes, EncryptionDecryptionCBC) {
    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);

    EXPECT_EQ(NO_ERROR, rc, "encryption - cbc mode");
    rc = memcmp(_state->shm_base, hwaes_ciphertext, sizeof(hwaes_ciphertext));
    EXPECT_EQ(0, rc, "wrong encryption result");

    rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);

    EXPECT_EQ(NO_ERROR, rc, "decryption - cbc mode");
    rc = memcmp(_state->shm_base, hwaes_plaintext, sizeof(hwaes_plaintext));
    EXPECT_EQ(0, rc, "wrong decryption result");
}

TEST_F(hwaes, EncryptionDecryptionCBCNoSHM) {
    uint8_t buf[sizeof(hwaes_plaintext)] = {0};
    memcpy(buf, hwaes_plaintext, sizeof(hwaes_plaintext));

    _state->args_encrypt.text_in = (struct hwcrypt_arg_in){
            .data_ptr = buf,
            .len = sizeof(buf),
    };
    _state->args_encrypt.text_out = (struct hwcrypt_arg_out){
            .data_ptr = buf,
            .len = sizeof(buf),
    };

    _state->args_decrypt.text_in = (struct hwcrypt_arg_in){
            .data_ptr = buf,
            .len = sizeof(buf),
    };
    _state->args_decrypt.text_out = (struct hwcrypt_arg_out){
            .data_ptr = buf,
            .len = sizeof(buf),
    };

    int rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);

    EXPECT_EQ(NO_ERROR, rc, "encryption - cbc mode");
    rc = memcmp(buf, hwaes_ciphertext, sizeof(hwaes_ciphertext));
    EXPECT_EQ(0, rc, "wrong encryption result");

    rc = hwaes_decrypt(_state->hwaes_session, &_state->args_decrypt);

    EXPECT_EQ(NO_ERROR, rc, "decryption - cbc mode");
    rc = memcmp(buf, hwaes_plaintext, sizeof(hwaes_plaintext));
    EXPECT_EQ(0, rc, "wrong decryption result");
}

TEST_F(hwaes, RunEncryptMany) {
    int rc;
    for (size_t i = 0; i < MAX_TRY_TIMES; i++) {
        rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
        ASSERT_EQ(NO_ERROR, rc, "encryption - in loop");
    }

    memcpy(_state->shm_base, hwaes_plaintext, sizeof(hwaes_plaintext));
    rc = hwaes_encrypt(_state->hwaes_session, &_state->args_encrypt);
    EXPECT_EQ(NO_ERROR, rc, "encryption - final round");
    rc = memcmp(_state->shm_base, hwaes_ciphertext, sizeof(hwaes_ciphertext));
    EXPECT_EQ(0, rc, "wrong encryption result");

test_abort:;
}

PORT_TEST(hwaes, "com.android.trusty.hwaes.test")
