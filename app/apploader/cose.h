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

#pragma once

#include <stddef.h>
#include <optional>
#include <vector>

// From https://tools.ietf.org/html/rfc8152
constexpr int COSE_LABEL_ALG = 1;
constexpr int COSE_LABEL_KID = 4;
constexpr int COSE_TAG_SIGN1 = 18;

// From "COSE Algorithms" registry
constexpr int COSE_ALG_ECDSA_256 = -7;

// Trusty-specific COSE constants
constexpr int COSE_LABEL_TRUSTY = -65537;

constexpr size_t kEcdsaValueSize = 32;
constexpr size_t kEcdsaSignatureSize = 2 * kEcdsaValueSize;

/**
 * coseSignEcDsa() - Sign the given data using ECDSA and emit a COSE CBOR blob.
 * @key:
 *      DER-encoded private key.
 * @keyId:
 *      Key identifier, an unsigned 1-byte integer.
 * @data:
 *      Block of data to sign and optionally encode inside the COSE signature
 *      structure.
 * @protectedHeaders:
 *      Protected headers for the COSE structure. The function may add its own
 *      additional entries.
 * @unprotectedHeaders:
 *      Unprotected headers for the COSE structure. The function may add its
 *      own additional entries.
 * @detachContent:
 *      Whether to detach the data, i.e., not include @data in the returned
 *      ```COSE_Sign1``` structure.
 * @tagged:
 *      Whether to return the tagged ```COSE_Sign1_Tagged``` or the untagged
 *      ```COSE_Sign1``` structure.
 *
 * This function signs a given block of data with ECDSA-SHA256 and encodes both
 * the data and the signature using the COSE encoding from RFC 8152. The caller
 * may specify whether the data is included or detached from the returned
 * structure using the @detachContent paramenter, as well as additional
 * context-specific header values with the @protectedHeaders and
 * @unprotectedHeaders parameters.
 *
 * Return: A unique pointer to a &struct cppbor::Item containing the
 *         ```COSE_Sign1``` structure if the signing algorithm succeeds,
 *         or an uninitalized pointer otherwise.
 */
std::unique_ptr<cppbor::Item> coseSignEcDsa(const std::vector<uint8_t>& key,
                                            uint8_t keyId,
                                            const std::vector<uint8_t>& data,
                                            cppbor::Map protectedHeaders,
                                            cppbor::Map unprotectedHeaders,
                                            bool detachContent,
                                            bool tagged);

/**
 * coseIsSigned() - Check if a block of bytes is a COSE signature emitted
 *                  by coseSignEcDsa().
 * @data:            Input data.
 * @signatureLength: If not NULL, output argument where the total length
 *                   of the signature structure will be stored.
 *
 * This function checks if the given data is a COSE signature structure
 * emitted by coseSignEcDsa(), and returns the size of the signature if needed.
 *
 * Return: %true if the signature structure is valid, %false otherwise.
 */
bool coseIsSigned(const std::vector<uint8_t>& data, size_t* signatureLength);

/**
 * coseCheckEcDsaSignature() - Check if a given COSE signature structure is
 *                             valid.
 * @signatureCoseSign1: Input COSE signature structure.
 * @detachedContent:    Additional data to include in the signature.
 *                      Corresponds to the @detachedContent parameter passed to
 *                      coseSignEcDsa().
 * @publicKey:          Public key in DER encoding.
 *
 * Returns: %true if the signature verification passes, %false otherwise.
 */
bool coseCheckEcDsaSignature(const std::vector<uint8_t>& signatureCoseSign1,
                             const std::vector<uint8_t>& detachedContent,
                             const std::vector<uint8_t>& publicKey);

/**
 * strictCheckEcDsaSignature() - Check a given COSE signature in strict mode.
 * @packageStart:       Pointer to the start of the signed input package.
 * @packageSize:        Size of the signed input package.
 * @keyFn:              Function to call with a key id that returns the public
 *                      key for that id.
 * @outPackageStart:    If not NULL, output argument where the start of the
 *                      payload will be stored.
 * @outPackageSize:     If not NULL, output argument where the size of the
 *                      payload will be stored.
 *
 * This function performs a strict verification of the COSE signature of a
 * package. Instead of parsing the COSE structure, the function compares the
 * raw bytes against a set of exact patterns, and fails if the bytes do not
 * match. The actual signature and payload are also assumed to start at fixed
 * offsets from @packageStart.
 *
 * Returns: %true if the signature verification passes, %false otherwise.
 */
bool strictCheckEcDsaSignature(
        const uint8_t* packageStart,
        size_t packageSize,
        std::function<std::tuple<std::unique_ptr<uint8_t[]>, size_t>(uint8_t)>
                keyFn,
        const uint8_t** outPackageStart,
        size_t* outPackageSize);
