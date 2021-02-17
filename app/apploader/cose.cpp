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

#define TLOG_TAG "apploader-cose"

#include <assert.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stddef.h>
#include <string.h>
#include <trusty_log.h>
#include <array>
#include <optional>
#include <vector>

#include "cose.h"

#ifdef __COSE_HOST__
#define COSE_PRINT_ERROR(...) fprintf(stderr, __VA_ARGS__)
#else
#define COSE_PRINT_ERROR(...) TLOGE(__VA_ARGS__)
#endif

using BIGNUM_Ptr = std::unique_ptr<BIGNUM, std::function<void(BIGNUM*)>>;
using EC_KEY_Ptr = std::unique_ptr<EC_KEY, std::function<void(EC_KEY*)>>;
using ECDSA_SIG_Ptr =
        std::unique_ptr<ECDSA_SIG, std::function<void(ECDSA_SIG*)>>;

using SHA256Digest = std::array<uint8_t, SHA256_DIGEST_LENGTH>;

static std::vector<uint8_t> coseBuildToBeSigned(
        const std::vector<uint8_t>& encodedProtectedHeaders,
        const std::vector<uint8_t>& data) {
    cppbor::Array sigStructure;
    sigStructure.add("Signature1");
    sigStructure.add(encodedProtectedHeaders);

    // We currently don't support Externally Supplied Data (RFC 8152
    // section 4.3) so external_aad is the empty bstr
    std::vector<uint8_t> emptyExternalAad;
    sigStructure.add(emptyExternalAad);
    sigStructure.add(data);
    return sigStructure.encode();
}

static std::vector<uint8_t> coseEncodeHeaders(
        const cppbor::Map& protectedHeaders) {
    if (protectedHeaders.size() == 0) {
        cppbor::Bstr emptyBstr(std::vector<uint8_t>({}));
        return emptyBstr.encode();
    }
    return protectedHeaders.encode();
}

static SHA256Digest sha256(const std::vector<uint8_t>& data) {
    SHA256Digest ret;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final((unsigned char*)ret.data(), &ctx);
    return ret;
}

static std::optional<std::vector<uint8_t>> signEcDsaDigest(
        const std::vector<uint8_t>& key,
        const SHA256Digest& dataDigest) {
    const unsigned char* k = key.data();
    auto ecKey =
            EC_KEY_Ptr(d2i_ECPrivateKey(nullptr, &k, key.size()), EC_KEY_free);
    if (!ecKey) {
        COSE_PRINT_ERROR("Error parsing EC private key\n");
        return {};
    }

    auto sig = ECDSA_SIG_Ptr(
            ECDSA_do_sign(dataDigest.data(), dataDigest.size(), ecKey.get()),
            ECDSA_SIG_free);
    if (!sig) {
        COSE_PRINT_ERROR("Error signing digest:\n");
        return {};
    }
    size_t len = i2d_ECDSA_SIG(sig.get(), nullptr);
    std::vector<uint8_t> signature;
    signature.resize(len);
    unsigned char* p = (unsigned char*)signature.data();
    i2d_ECDSA_SIG(sig.get(), &p);
    return signature;
}

static std::optional<std::vector<uint8_t>> signEcDsa(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data) {
    return signEcDsaDigest(key, sha256(data));
}

static bool ecdsaSignatureDerToCose(
        const std::vector<uint8_t>& ecdsaDerSignature,
        std::vector<uint8_t>& ecdsaCoseSignature) {
    const unsigned char* p = ecdsaDerSignature.data();
    auto sig =
            ECDSA_SIG_Ptr(d2i_ECDSA_SIG(nullptr, &p, ecdsaDerSignature.size()),
                          ECDSA_SIG_free);
    if (!sig) {
        COSE_PRINT_ERROR("Error decoding DER signature\n");
        return false;
    }

    const BIGNUM* rBn;
    const BIGNUM* sBn;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /*
     * OpenSSL 1.1.0 changes ECDSA_SIG to an opaque structure
     * and introduces a getter and setter for the R and S values.
     * Previous versions just exposed the structure to users.
     */
    rBn = sig->r;
    sBn = sig->s;
#else
    ECDSA_SIG_get0(sig.get(), &rBn, &sBn);
#endif

    /*
     * Older versions of OpenSSL also do not have BN_bn2binpad,
     * so we need to use BN_bn2bin with the correct offsets.
     * Each of the output values is a 32-byte big-endian number,
     * while the inputs are BIGNUMs stored in host format.
     * We can insert the padding ourselves by zeroing the output array,
     * then placing the output of BN_bn2bin so its end aligns
     * with the end of the 32-byte big-endian number.
     */
    auto rBnSize = BN_num_bytes(rBn);
    if (rBnSize < 0 || static_cast<size_t>(rBnSize) > kEcdsaValueSize) {
        COSE_PRINT_ERROR("Invalid ECDSA r value size (%d)\n", rBnSize);
        return false;
    }
    auto sBnSize = BN_num_bytes(sBn);
    if (sBnSize < 0 || static_cast<size_t>(sBnSize) > kEcdsaValueSize) {
        COSE_PRINT_ERROR("Invalid ECDSA s value size (%d)\n", sBnSize);
        return false;
    }

    ecdsaCoseSignature.clear();
    ecdsaCoseSignature.resize(kEcdsaSignatureSize, 0);
    if (BN_bn2bin(rBn, ecdsaCoseSignature.data() + kEcdsaValueSize - rBnSize) !=
        kEcdsaValueSize) {
        COSE_PRINT_ERROR("Error encoding r\n");
        return false;
    }
    if (BN_bn2bin(sBn, ecdsaCoseSignature.data() + kEcdsaSignatureSize -
                               sBnSize) != kEcdsaValueSize) {
        COSE_PRINT_ERROR("Error encoding s\n");
        return false;
    }
    return true;
}

std::unique_ptr<cppbor::Item> coseSignEcDsa(const std::vector<uint8_t>& key,
                                            uint8_t keyId,
                                            const std::vector<uint8_t>& data,
                                            cppbor::Map protectedHeaders,
                                            cppbor::Map unprotectedHeaders,
                                            bool detachContent,
                                            bool tagged) {
    protectedHeaders.add(COSE_LABEL_ALG, COSE_ALG_ECDSA_256);
    unprotectedHeaders.add(COSE_LABEL_KID, cppbor::Bstr(std::vector(1, keyId)));

    // Canonicalize the headers to ensure a predictable layout
    protectedHeaders.canonicalize(true);
    unprotectedHeaders.canonicalize(true);

    std::vector<uint8_t> encodedProtectedHeaders =
            coseEncodeHeaders(protectedHeaders);
    std::vector<uint8_t> toBeSigned =
            coseBuildToBeSigned(encodedProtectedHeaders, data);

    std::optional<std::vector<uint8_t>> derSignature =
            signEcDsa(key, toBeSigned);
    if (!derSignature) {
        COSE_PRINT_ERROR("Error signing toBeSigned data\n");
        return {};
    }
    std::vector<uint8_t> coseSignature;
    if (!ecdsaSignatureDerToCose(derSignature.value(), coseSignature)) {
        COSE_PRINT_ERROR(
                "Error converting ECDSA signature from DER to COSE format\n");
        return {};
    }

    auto coseSign1 = std::make_unique<cppbor::Array>();
    coseSign1->add(encodedProtectedHeaders);
    coseSign1->add(std::move(unprotectedHeaders));
    if (detachContent) {
        cppbor::Null nullValue;
        coseSign1->add(std::move(nullValue));
    } else {
        coseSign1->add(data);
    }
    coseSign1->add(coseSignature);

    if (tagged) {
        return std::make_unique<cppbor::SemanticTag>(COSE_TAG_SIGN1,
                                                     coseSign1.release());
    } else {
        return coseSign1;
    }
}

bool coseIsSigned(const std::vector<uint8_t>& data, size_t* signatureLength) {
    auto [item, pos, err] = cppbor::parse(data);
    if (item) {
        for (size_t i = 0; i < item->semanticTagCount(); i++) {
            if (item->semanticTag(i) == COSE_TAG_SIGN1) {
                if (signatureLength) {
                    *signatureLength = std::distance(data.data(), pos);
                }
                return true;
            }
        }
    }
    return false;
}

static std::unique_ptr<uint8_t[]> ecdsaSignatureCoseToDer(
        const uint8_t* ecdsaCoseSignature,
        size_t* outSignatureSize) {
    auto rBn = BIGNUM_Ptr(
            BN_bin2bn(ecdsaCoseSignature, kEcdsaValueSize, nullptr), BN_free);
    if (rBn.get() == nullptr) {
        COSE_PRINT_ERROR("Error creating BIGNUM for r\n");
        return {};
    }

    auto sBn = BIGNUM_Ptr(BN_bin2bn(ecdsaCoseSignature + kEcdsaValueSize,
                                    kEcdsaValueSize, nullptr),
                          BN_free);
    if (sBn.get() == nullptr) {
        COSE_PRINT_ERROR("Error creating BIGNUM for s\n");
        return {};
    }

    auto sig = ECDSA_SIG_Ptr(ECDSA_SIG_new(), ECDSA_SIG_free);
    if (!sig) {
        COSE_PRINT_ERROR("Error allocating ECDSA_SIG\n");
        return {};
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* See comment on OpenSSL 1.1.0 in ecdsaSignatureDerToCose */
    sig->r = rBn.release();
    sig->s = sBn.release();
#else
    ECDSA_SIG_set0(sig.get(), rBn.release(), sBn.release());
#endif

    size_t len = i2d_ECDSA_SIG(sig.get(), nullptr);
    std::unique_ptr<uint8_t[]> ecdsaDerSignature(new (std::nothrow)
                                                         uint8_t[len]);
    if (!ecdsaDerSignature) {
        return {};
    }

    unsigned char* p = (unsigned char*)ecdsaDerSignature.get();
    i2d_ECDSA_SIG(sig.get(), &p);

    if (outSignatureSize != nullptr) {
        *outSignatureSize = len;
    }

    return ecdsaDerSignature;
}

static bool checkEcDsaSignature(const SHA256Digest& digest,
                                uint8_t* signature,
                                size_t signatureSize,
                                const uint8_t* publicKey,
                                size_t publicKeySize) {
    const unsigned char* p = (unsigned char*)signature;
    auto sig = ECDSA_SIG_Ptr(d2i_ECDSA_SIG(nullptr, &p, signatureSize),
                             ECDSA_SIG_free);
    if (sig.get() == nullptr) {
        COSE_PRINT_ERROR("Error decoding DER encoded signature\n");
        return false;
    }

    const unsigned char* k = publicKey;
    auto ecKey =
            EC_KEY_Ptr(d2i_EC_PUBKEY(nullptr, &k, publicKeySize), EC_KEY_free);
    if (!ecKey) {
        COSE_PRINT_ERROR("Error parsing EC public key\n");
        return false;
    }

    int rc = ECDSA_do_verify(digest.data(), digest.size(), sig.get(),
                             ecKey.get());
    if (rc != 1) {
        COSE_PRINT_ERROR("Error verifying signature (rc=%d)\n", rc);
        return false;
    }

    return true;
}

bool coseCheckEcDsaSignature(const std::vector<uint8_t>& signatureCoseSign1,
                             const std::vector<uint8_t>& detachedContent,
                             const std::vector<uint8_t>& publicKey) {
    auto [item, _, message] = cppbor::parse(signatureCoseSign1);
    if (item == nullptr) {
        COSE_PRINT_ERROR("Passed-in COSE_Sign1 is not valid CBOR\n");
        return false;
    }
    const cppbor::Array* array = item->asArray();
    if (array == nullptr) {
        COSE_PRINT_ERROR("Value for COSE_Sign1 is not an array\n");
        return false;
    }
    if (array->size() != 4) {
        COSE_PRINT_ERROR("Value for COSE_Sign1 is not an array of size 4\n");
        return false;
    }

    const cppbor::Bstr* encodedProtectedHeadersBstr = (*array)[0]->asBstr();
    if (encodedProtectedHeadersBstr == nullptr) {
        COSE_PRINT_ERROR("Value for encodedProtectedHeaders is not a bstr\n");
        return false;
    }
    const std::vector<uint8_t> encodedProtectedHeaders =
            encodedProtectedHeadersBstr->value();

    const cppbor::Map* unprotectedHeaders = (*array)[1]->asMap();
    if (unprotectedHeaders == nullptr) {
        COSE_PRINT_ERROR("Value for unprotectedHeaders is not a map\n");
        return false;
    }

    std::vector<uint8_t> data;
    const cppbor::Simple* payloadAsSimple = (*array)[2]->asSimple();
    if (payloadAsSimple != nullptr) {
        if (payloadAsSimple->asNull() == nullptr) {
            COSE_PRINT_ERROR("Value for payload is not null or a bstr\n");
            return false;
        }
    } else {
        const cppbor::Bstr* payloadAsBstr = (*array)[2]->asBstr();
        if (payloadAsBstr == nullptr) {
            COSE_PRINT_ERROR("Value for payload is not null or a bstr\n");
            return false;
        }
        data = payloadAsBstr->value();  // TODO: avoid copy
    }

    if (data.size() > 0 && detachedContent.size() > 0) {
        COSE_PRINT_ERROR("data and detachedContent cannot both be non-empty\n");
        return false;
    }

    const cppbor::Bstr* signatureBstr = (*array)[3]->asBstr();
    if (signatureBstr == nullptr) {
        COSE_PRINT_ERROR("Value for signature is not a bstr\n");
        return false;
    }
    const std::vector<uint8_t>& coseSignature = signatureBstr->value();
    if (coseSignature.size() != kEcdsaSignatureSize) {
        COSE_PRINT_ERROR("COSE signature length is %zu, expected %zu\n",
                         coseSignature.size(), kEcdsaSignatureSize);
        return false;
    }

    size_t derSignatureLen;
    auto derSignature =
            ecdsaSignatureCoseToDer(coseSignature.data(), &derSignatureLen);
    if (!derSignature) {
        COSE_PRINT_ERROR(
                "Error converting ECDSA signature from COSE to DER format\n");
        return false;
    }

    // The last field is the payload, independently of how it's transported (RFC
    // 8152 section 4.4). Since our API specifies only one of |data| and
    // |detachedContent| can be non-empty, it's simply just the non-empty one.
    auto& signaturePayload = data.size() > 0 ? data : detachedContent;
    std::vector<uint8_t> toBeSigned =
            coseBuildToBeSigned(encodedProtectedHeaders, signaturePayload);
    if (!checkEcDsaSignature(sha256(toBeSigned), derSignature.get(),
                             derSignatureLen, publicKey.data(),
                             publicKey.size())) {
        COSE_PRINT_ERROR("Signature check failed\n");
        return false;
    }
    return true;
}

/*
 * Strict signature verification code
 */
static const uint8_t kSignatureHeader[] = {
        // CBOR bytes
        0xD2,
        0x84,
        0x54,
        0xA2,
        0x01,
        // Algorithm identifier
        0x26,
        // CBOR bytes
        0x3A,
        0x00,
        0x01,
        0x00,
        0x00,
        0x82,
        0x69,
        // "TrustyApp"
        0x54,
        0x72,
        0x75,
        0x73,
        0x74,
        0x79,
        0x41,
        0x70,
        0x70,
        // Version
        0x01,
        // CBOR bytes
        0xA1,
        0x04,
        0x41,
};
static const uint8_t kSignatureHeaderPart2[] = {0xF6, 0x58, 0x40};
static const uint8_t kSignature1Header[] = {
        // CBOR bytes
        0x84,
        0x6A,
        // "Signature1"
        0x53,
        0x69,
        0x67,
        0x6E,
        0x61,
        0x74,
        0x75,
        0x72,
        0x65,
        0x31,
        // CBOR bytes
        0x54,
        0xA2,
        0x01,
        // Algorithm identifier
        0x26,
        // CBOR bytes
        0x3A,
        0x00,
        0x01,
        0x00,
        0x00,
        0x82,
        0x69,
        // "TrustyApp"
        0x54,
        0x72,
        0x75,
        0x73,
        0x74,
        0x79,
        0x41,
        0x70,
        0x70,
        // Version
        0x01,
        // CBOR bytes
        0x40,
};

/*
 * Fixed offset constants
 */
constexpr size_t kSignatureKeyIdOffset = sizeof(kSignatureHeader);
constexpr size_t kSignatureHeaderPart2Offset = kSignatureKeyIdOffset + 1;
constexpr size_t kSignatureOffset =
        kSignatureHeaderPart2Offset + sizeof(kSignatureHeaderPart2);
constexpr size_t kPayloadOffset = kSignatureOffset + kEcdsaSignatureSize;

bool strictCheckEcDsaSignature(
        const uint8_t* packageStart,
        size_t packageSize,
        std::function<std::tuple<std::unique_ptr<uint8_t[]>, size_t>(uint8_t)>
                keyFn,
        const uint8_t** outPackageStart,
        size_t* outPackageSize) {
    if (packageSize < kPayloadOffset) {
        COSE_PRINT_ERROR("Passed-in COSE_Sign1 is not large enough\n");
        return false;
    }

    if (CRYPTO_memcmp(packageStart, kSignatureHeader,
                      sizeof(kSignatureHeader))) {
        COSE_PRINT_ERROR("Passed-in COSE_Sign1 is not valid CBOR\n");
        return false;
    }

    uint8_t kid = packageStart[kSignatureKeyIdOffset];
    auto [publicKey, publicKeySize] = keyFn(kid);
    if (!publicKey) {
        COSE_PRINT_ERROR("Failed to retrieve public key\n");
        return false;
    }

    if (CRYPTO_memcmp(packageStart + kSignatureHeaderPart2Offset,
                      kSignatureHeaderPart2, sizeof(kSignatureHeaderPart2))) {
        COSE_PRINT_ERROR("Passed-in COSE_Sign1 is not valid CBOR\n");
        return false;
    }

    size_t derSignatureSize;
    auto derSignature = ecdsaSignatureCoseToDer(packageStart + kSignatureOffset,
                                                &derSignatureSize);
    if (!derSignature) {
        COSE_PRINT_ERROR(
                "Error converting ECDSA signature from COSE to DER format\n");
        return false;
    }

    // The Signature1 structure encodes the payload as a bstr wrapping the
    // actual contents (even if they already are CBOR), so we need to manually
    // prepend a CBOR bstr header to the payload
    constexpr size_t kMaxPayloadSizeHeaderSize = 9;
    size_t payloadSize = packageSize - kPayloadOffset;
    size_t payloadSizeHeaderSize = cppbor::headerSize(payloadSize);
    assert(payloadSizeHeaderSize <= kMaxPayloadSizeHeaderSize);

    uint8_t payloadSizeHeader[kMaxPayloadSizeHeaderSize];
    const uint8_t* payloadHeaderEnd =
            cppbor::encodeHeader(cppbor::BSTR, payloadSize, payloadSizeHeader,
                                 payloadSizeHeader + kMaxPayloadSizeHeaderSize);
    assert(payloadHeaderEnd == payloadSizeHeader + payloadSizeHeaderSize);

    SHA256Digest digest;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, kSignature1Header, sizeof(kSignature1Header));
    SHA256_Update(&ctx, payloadSizeHeader, payloadSizeHeaderSize);
    SHA256_Update(&ctx, packageStart + kPayloadOffset, payloadSize);
    SHA256_Final(digest.data(), &ctx);

    if (!checkEcDsaSignature(digest, derSignature.get(), derSignatureSize,
                             publicKey.get(), publicKeySize)) {
        COSE_PRINT_ERROR("Signature check failed\n");
        return false;
    }

    if (outPackageStart != nullptr) {
        *outPackageStart = packageStart + kPayloadOffset;
    }
    if (outPackageSize != nullptr) {
        *outPackageSize = payloadSize;
    }
    return true;
}
