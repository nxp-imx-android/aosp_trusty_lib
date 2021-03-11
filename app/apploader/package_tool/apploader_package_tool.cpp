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

#include <cppbor.h>
#include <cppbor_parse.h>
#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <interface/apploader/apploader_package.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "../cose.h"

enum class Mode {
    UNKNOWN,
    BUILD,
    SIGN,
    VERIFY,
    ENCRYPT,
    DECRYPT,
};

static Mode mode = Mode::UNKNOWN;
static bool strict = false;

static const char* _sopts = "hm:s";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"mode", required_argument, 0, 'm'},
        {"strict", no_argument, 0, 's'},
        {0, 0, 0, 0},
};

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\t%s --mode <mode> [options] ...\n", prog);
    fprintf(stderr, "\t%s --mode build [options] <output> <ELF> <manifest>\n",
            prog);
    fprintf(stderr,
            "\t%s --mode sign [options] <output> <input> <key> <key id>\n",
            prog);
    fprintf(stderr, "\t%s --mode verify [options] <input> <key>\n", prog);
    fprintf(stderr,
            "\t%s --mode encrypt [options] <output> <input> <key> <key id>\n",
            prog);
    fprintf(stderr, "\t%s --mode decrypt [options] <output> <input> <key>\n",
            prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-h, --help            prints this message and exit\n");
    fprintf(stderr,
            "\t-m, --mode            mode; one of: build, sign, verify, encrypt\n");
    fprintf(stderr,
            "\t-s, --strict          verify signature in strict mode\n");
    fprintf(stderr, "\n");
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
        case 'h':
            print_usage_and_exit(argv[0], EXIT_SUCCESS);
            break;

        case 'm':
            if (!strcmp(optarg, "build")) {
                mode = Mode::BUILD;
            } else if (!strcmp(optarg, "sign")) {
                mode = Mode::SIGN;
            } else if (!strcmp(optarg, "verify")) {
                mode = Mode::VERIFY;
            } else if (!strcmp(optarg, "encrypt")) {
                mode = Mode::ENCRYPT;
            } else if (!strcmp(optarg, "decrypt")) {
                mode = Mode::DECRYPT;
            } else {
                fprintf(stderr, "Unrecognized command mode: %s\n", optarg);
                /*
                 * Set the mode to UNKNOWN so main prints the usage and exits
                 */
                mode = Mode::UNKNOWN;
            }
            break;

        case 's':
            strict = true;
            break;

        default:
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static std::string read_entire_file(const char* file_name) {
    /*
     * Disable synchronization between C++ streams and FILE* functions for a
     * performance boost
     */
    std::ios::sync_with_stdio(false);

    std::ifstream ifs(file_name, std::ios::in | std::ios::binary);
    if (!ifs || !ifs.is_open()) {
        fprintf(stderr, "Failed to open file '%s'\n", file_name);
        exit(EXIT_FAILURE);
    }

    std::ostringstream ss;
    ss << ifs.rdbuf();
    if (!ss) {
        fprintf(stderr, "Failed to read file '%s'\n", file_name);
        exit(EXIT_FAILURE);
    }

    return ss.str();
}

static void write_entire_file(const char* file_name,
                              const std::vector<uint8_t>& data) {
    /*
     * Disable synchronization between C++ streams and FILE* functions for a
     * performance boost
     */
    std::ios::sync_with_stdio(false);

    std::ofstream ofs(file_name,
                      std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs || !ofs.is_open()) {
        fprintf(stderr, "Failed to create file '%s'\n", file_name);
        exit(EXIT_FAILURE);
    }

    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!ofs) {
        fprintf(stderr, "Failed to write to file '%s'\n", file_name);
        exit(EXIT_FAILURE);
    }
}

static void build_package(const char* output_path,
                          const char* elf_path,
                          const char* manifest_path) {
    auto elf = read_entire_file(elf_path);
    auto manifest = read_entire_file(manifest_path);

    cppbor::Map headers;

    cppbor::Array untagged_package;
    untagged_package.add(APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT);
    untagged_package.add(std::move(headers));
    untagged_package.add(cppbor::Bstr(std::move(elf)));
    untagged_package.add(cppbor::Bstr(std::move(manifest)));

    cppbor::SemanticTag tagged_package(APPLOADER_PACKAGE_CBOR_TAG_APP,
                                       std::move(untagged_package));
    auto encoded_package = tagged_package.encode();
    write_entire_file(output_path, encoded_package);
}

static std::vector<uint8_t> string_to_vector(std::string s) {
    auto* start_ptr = reinterpret_cast<uint8_t*>(s.data());
    return {start_ptr, start_ptr + s.size()};
}

static uint8_t parse_key_id(const char* key_id) {
    std::string key_id_str{key_id};
    size_t key_id_end;
    int int_key_id = std::stoi(key_id_str, &key_id_end);
    if (key_id_end < key_id_str.size()) {
        fprintf(stderr, "Invalid key id: %s\n", key_id);
        exit(EXIT_FAILURE);
    }
    if (int_key_id < std::numeric_limits<uint8_t>::min() ||
        int_key_id > std::numeric_limits<uint8_t>::max()) {
        fprintf(stderr, "Key id out of range: %d\n", int_key_id);
        exit(EXIT_FAILURE);
    }
    return static_cast<uint8_t>(int_key_id);
}

static void sign_package(const char* output_path,
                         const char* input_path,
                         const char* key_path,
                         uint8_t key_id) {
    auto input = string_to_vector(read_entire_file(input_path));
    if (coseIsSigned(input, nullptr)) {
        fprintf(stderr, "Input file is already signed\n");
        exit(EXIT_FAILURE);
    }

    cppbor::Map protected_headers;
    cppbor::Array trusty_array;
    trusty_array.add("TrustyApp");
    trusty_array.add(APPLOADER_SIGNATURE_FORMAT_VERSION_CURRENT);
    protected_headers.add(COSE_LABEL_TRUSTY, std::move(trusty_array));

    auto key = string_to_vector(read_entire_file(key_path));
    auto sig = coseSignEcDsa(key, key_id, input, std::move(protected_headers),
                             {}, true, true);
    if (!sig) {
        fprintf(stderr, "Failed to sign package\n");
        exit(EXIT_FAILURE);
    }

    auto full_sig = sig->encode();
    full_sig.insert(full_sig.end(), input.begin(), input.end());
    write_entire_file(output_path, full_sig);
}

static void verify_package(const char* input_path, const char* key_path) {
    auto input = string_to_vector(read_entire_file(input_path));
    size_t signature_length;
    if (!coseIsSigned(input, &signature_length)) {
        fprintf(stderr, "Input file is not signed\n");
        exit(EXIT_FAILURE);
    }

    auto key = string_to_vector(read_entire_file(key_path));
    bool signature_ok;
    if (strict) {
        auto get_key = [&key](uint8_t key_id)
                -> std::tuple<std::unique_ptr<uint8_t[]>, size_t> {
            auto key_data = std::make_unique<uint8_t[]>(key.size());
            if (!key_data) {
                return {};
            }

            memcpy(key_data.get(), key.data(), key.size());
            return {std::move(key_data), key.size()};
        };
        signature_ok = strictCheckEcDsaSignature(input.data(), input.size(),
                                                 get_key, nullptr, nullptr);
    } else {
        std::vector<uint8_t> payload(input.begin() + signature_length,
                                     input.end());
        input.resize(signature_length);
        signature_ok = coseCheckEcDsaSignature(input, payload, key);
    }

    if (!signature_ok) {
        fprintf(stderr, "Signature verification failed\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Signature verification passed\n");
}

static void update_header_content_is_cose_encrypt(cppbor::Map* headers,
                                                  bool new_value) {
    // Walk the entire headers map to replace the content type value.
    // We need to do this because cppbor::Map::get() returns a const reference.
    bool found = false;
    for (auto& [label_item, value_item] : *headers) {
        auto* label_uint = label_item->asUint();
        if (label_uint != nullptr &&
            label_uint->unsignedValue() ==
                    APPLOADER_PACKAGE_HEADER_LABEL_CONTENT_IS_COSE_ENCRYPT) {
            if (found) {
                fprintf(stderr,
                        "Duplicate content_is_cose_encrypt header fields\n");
                exit(EXIT_FAILURE);
            }
            found = true;

            auto* content_is_cose_encrypt_simple = value_item->asSimple();
            if (content_is_cose_encrypt_simple == nullptr) {
                fprintf(stderr,
                        "Invalid content_is_cose_encrypt CBOR type, "
                        "got: 0x%x\n",
                        static_cast<int>(value_item->type()));
                exit(EXIT_FAILURE);
            }

            auto* content_is_cose_encrypt_bool =
                    content_is_cose_encrypt_simple->asBool();
            if (content_is_cose_encrypt_bool == nullptr) {
                fprintf(stderr,
                        "Invalid content_is_cose_encrypt CBOR simple type, "
                        "got: 0x%x\n",
                        static_cast<int>(
                                content_is_cose_encrypt_simple->simpleType()));
                exit(EXIT_FAILURE);
            }

            if (content_is_cose_encrypt_bool->value() == new_value) {
                fprintf(stderr, "Invalid content_is_cose_encrypt value\n");
                exit(EXIT_FAILURE);
            }

            // Update the content flag
            value_item = std::make_unique<cppbor::Bool>(new_value);
        }
    }

    if (new_value && !found) {
        headers->add(APPLOADER_PACKAGE_HEADER_LABEL_CONTENT_IS_COSE_ENCRYPT,
                     cppbor::Bool(true));
        headers->canonicalize(true);
    }
}

static void encrypt_package(const char* output_path,
                            const char* input_path,
                            const char* key_path,
                            uint8_t key_id) {
    auto input = read_entire_file(input_path);
    auto [item, pos, err] = cppbor::parse(
            reinterpret_cast<uint8_t*>(input.data()), input.size());
    if (!item) {
        fprintf(stderr, "Failed to parse input file as CBOR\n");
        exit(EXIT_FAILURE);
    }

    bool found_app_tag = false;
    for (size_t i = 0; i < item->semanticTagCount(); i++) {
        if (item->semanticTag(i) == COSE_TAG_SIGN1) {
            fprintf(stderr, "Input file is already signed\n");
            exit(EXIT_FAILURE);
        }
        if (item->semanticTag(i) == APPLOADER_PACKAGE_CBOR_TAG_APP) {
            found_app_tag = true;
        }
    }

    if (!found_app_tag) {
        fprintf(stderr, "Input file is not a Trusty application package\n");
        exit(EXIT_FAILURE);
    }

    auto* pkg_array = item->asArray();
    if (pkg_array == nullptr) {
        fprintf(stderr, "Invalid input file format\n");
        exit(EXIT_FAILURE);
    }

    if (pkg_array->size() != 4) {
        fprintf(stderr, "Invalid number of CBOR array elements: %zd\n",
                pkg_array->size());
        exit(EXIT_FAILURE);
    }

    auto* version = pkg_array->get(0)->asUint();
    if (version == nullptr) {
        fprintf(stderr, "Invalid version field CBOR type, got: 0x%x\n",
                static_cast<int>(pkg_array->get(0)->type()));
        exit(EXIT_FAILURE);
    }
    if (version->unsignedValue() != APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT) {
        fprintf(stderr,
                "Invalid package version, expected %" PRIu64 " got %" PRIu64
                "\n",
                APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT,
                version->unsignedValue());
        exit(EXIT_FAILURE);
    }

    auto* headers = pkg_array->get(1)->asMap();
    if (headers == nullptr) {
        fprintf(stderr, "Invalid headers CBOR type, got: 0x%x\n",
                static_cast<int>(pkg_array->get(1)->type()));
        exit(EXIT_FAILURE);
    }

    auto* elf = pkg_array->get(2)->asBstr();
    if (elf == nullptr) {
        fprintf(stderr, "Invalid ELF CBOR type, got: 0x%x\n",
                static_cast<int>(pkg_array->get(2)->type()));
        exit(EXIT_FAILURE);
    }

    auto key = string_to_vector(read_entire_file(key_path));
    if (key.size() != kAes128GcmKeySize) {
        fprintf(stderr, "Wrong AES-128-GCM key size: %zu\n", key.size());
        exit(EXIT_FAILURE);
    }

    cppbor::Map protected_headers;
    protected_headers.add(COSE_LABEL_TRUSTY, "TrustyApp");

    std::vector<uint8_t> elf_vec(elf->value().begin(), elf->value().end());
    auto cose_encrypt = coseEncryptAes128GcmKeyWrap(
            key, key_id, elf_vec, {}, std::move(protected_headers), {}, false);
    if (!cose_encrypt) {
        fprintf(stderr, "Failed to encrypt ELF file\n");
        exit(EXIT_FAILURE);
    }

    auto enc_headers = headers->clone();
    update_header_content_is_cose_encrypt(enc_headers->asMap(), true);

    // Build a new encrypted array since the original array has a semantic
    // tag that we do not want to preserve.
    cppbor::Array encrypted_array{
            std::move(pkg_array->get(0)),
            std::move(enc_headers),
            std::move(cose_encrypt),
            std::move(pkg_array->get(3)),
    };

    cppbor::SemanticTag tagged_package(APPLOADER_PACKAGE_CBOR_TAG_APP,
                                       std::move(encrypted_array));
    auto encoded_package = tagged_package.encode();
    write_entire_file(output_path, encoded_package);
}

static void decrypt_package(const char* output_path,
                            const char* input_path,
                            const char* key_path) {
    auto input = read_entire_file(input_path);
    auto [item, pos, err] = cppbor::parseWithViews(
            reinterpret_cast<uint8_t*>(input.data()), input.size());
    if (!item) {
        fprintf(stderr, "Failed to parse input file as CBOR\n");
        exit(EXIT_FAILURE);
    }

    bool found_app_tag = false;
    for (size_t i = 0; i < item->semanticTagCount(); i++) {
        if (item->semanticTag(i) == COSE_TAG_SIGN1) {
            fprintf(stderr, "Input file is already signed\n");
            exit(EXIT_FAILURE);
        }
        if (item->semanticTag(i) == APPLOADER_PACKAGE_CBOR_TAG_APP) {
            found_app_tag = true;
        }
    }

    if (!found_app_tag) {
        fprintf(stderr, "Input file is not a Trusty application package\n");
        exit(EXIT_FAILURE);
    }

    auto* pkg_array = item->asArray();
    if (pkg_array == nullptr) {
        fprintf(stderr, "Invalid input file format\n");
        exit(EXIT_FAILURE);
    }

    if (pkg_array->size() != 4) {
        fprintf(stderr, "Invalid number of CBOR array elements: %zd\n",
                pkg_array->size());
        exit(EXIT_FAILURE);
    }

    auto version = pkg_array->get(0)->asUint();
    if (version == nullptr) {
        fprintf(stderr, "Invalid version field CBOR type, got: 0x%x\n",
                static_cast<int>(pkg_array->get(0)->type()));
        exit(EXIT_FAILURE);
    }
    if (version->unsignedValue() != APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT) {
        fprintf(stderr,
                "Invalid package version, expected %" PRIu64 " got %" PRIu64
                "\n",
                APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT,
                version->unsignedValue());
        exit(EXIT_FAILURE);
    }

    auto* headers = pkg_array->get(1)->asMap();
    if (headers == nullptr) {
        fprintf(stderr, "Invalid headers CBOR type, got: 0x%x\n",
                static_cast<int>(pkg_array->get(1)->type()));
        exit(EXIT_FAILURE);
    }

    auto& elf = pkg_array->get(2);
    if (elf->asArray() == nullptr) {
        fprintf(stderr, "Invalid ELF CBOR type, got: 0x%x\n",
                static_cast<int>(elf->type()));
        exit(EXIT_FAILURE);
    }

    auto key = string_to_vector(read_entire_file(key_path));
    if (key.size() != kAes128GcmKeySize) {
        fprintf(stderr, "Wrong AES-128-GCM key size: %zu\n", key.size());
        exit(EXIT_FAILURE);
    }

    auto get_key = [&key](
            uint8_t key_id) -> std::tuple<std::unique_ptr<uint8_t[]>, size_t> {
        auto key_data = std::make_unique<uint8_t[]>(key.size());
        if (!key_data) {
            return {};
        }

        memcpy(key_data.get(), key.data(), key.size());
        return {std::move(key_data), key.size()};
    };

    const uint8_t* package_start;
    size_t package_size;
    if (!coseDecryptAes128GcmKeyWrapInPlace(elf, get_key, {}, false,
                                            &package_start, &package_size)) {
        fprintf(stderr, "Failed to decrypt ELF file\n");
        exit(EXIT_FAILURE);
    }

    auto dec_headers = headers->clone();
    update_header_content_is_cose_encrypt(dec_headers->asMap(), false);

    // Build a new decrypted array since the original array has a semantic
    // tag that we do not want to preserve.
    cppbor::Array decrypted_array{
            std::move(pkg_array->get(0)),
            std::move(dec_headers),
            std::make_pair(package_start, package_size),
            std::move(pkg_array->get(3)),
    };

    cppbor::SemanticTag tagged_package(APPLOADER_PACKAGE_CBOR_TAG_APP,
                                       std::move(decrypted_array));
    auto encoded_package = tagged_package.encode();
    write_entire_file(output_path, encoded_package);
}

int main(int argc, char** argv) {
    parse_options(argc, argv);

    switch (mode) {
    case Mode::BUILD:
        if (optind + 3 != argc) {
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
        build_package(argv[optind], argv[optind + 1], argv[optind + 2]);
        break;

    case Mode::SIGN:
        if (optind + 4 != argc) {
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
        sign_package(argv[optind], argv[optind + 1], argv[optind + 2],
                     parse_key_id(argv[optind + 3]));
        break;

    case Mode::VERIFY:
        if (optind + 2 != argc) {
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
        verify_package(argv[optind], argv[optind + 1]);
        break;

    case Mode::ENCRYPT:
        if (optind + 4 != argc) {
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
        encrypt_package(argv[optind], argv[optind + 1], argv[optind + 2],
                        parse_key_id(argv[optind + 3]));
        break;

    case Mode::DECRYPT:
        if (optind + 3 != argc) {
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
        decrypt_package(argv[optind], argv[optind + 1], argv[optind + 2]);
        break;

    default:
        print_usage_and_exit(argv[0], EXIT_FAILURE);
        break;
    }

    return 0;
}
