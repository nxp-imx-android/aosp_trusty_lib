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
#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <interface/apploader/apploader_package.h>
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
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-h, --help            prints this message and exit\n");
    fprintf(stderr,
            "\t-m, --mode            mode; one of: build, sign, verify\n");
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

    cppbor::Map headers{};

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

    default:
        print_usage_and_exit(argv[0], EXIT_FAILURE);
        break;
    }

    return 0;
}
