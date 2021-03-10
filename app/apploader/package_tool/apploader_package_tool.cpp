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

#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
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

/* TODO: these will go away after the COSE/CBOR format is added */
#define APPLOADER_PACKAGE_MAGIC "TrustyAp"
#define APPLOADER_PACKAGE_MAGIC_SIZE 8
#define APPLOADER_RECORD_TYPE_SHIFT 48
#define APPLOADER_RECORD_TYPE_ELF 0UL
#define APPLOADER_RECORD_TYPE_MANIFEST 1UL

enum class Mode {
    UNKNOWN,
    BUILD,
};

static Mode mode = Mode::UNKNOWN;

static const char* _sopts = "hm:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"mode", required_argument, 0, 'm'},
        {0, 0, 0, 0},
};

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\t%s --mode <mode> [options] ...\n", prog);
    fprintf(stderr, "\t%s --mode build [options] <output> <ELF> <manifest>\n",
            prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "\t-h, --help            prints this message and exit\n");
    fprintf(stderr, "\t-m, --mode            mode; one of: build\n");
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
            } else {
                fprintf(stderr, "Unrecognized command mode: %s\n", optarg);
                /*
                 * Set the mode to UNKNOWN so main prints the usage and exits
                 */
                mode = Mode::UNKNOWN;
            }
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

static void write_to_fd(int fd, const uint8_t* data, size_t len) {
    for (size_t off = 0; off < len;) {
        ssize_t num = write(fd, data + off, len - off);
        if (num < 0) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(stderr, "Failed to write to file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        off += num;
    }
}

static void build_package(const char* output_path,
                          const char* elf_path,
                          const char* manifest_path) {
    int fd = creat(output_path, 0644);
    if (fd < 0) {
        fprintf(stderr, "Failed to create file '%s': %s\n", output_path,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* TODO: rewrite these to use the new COSE/CBOR format */
    write_to_fd(fd, reinterpret_cast<const uint8_t*>(APPLOADER_PACKAGE_MAGIC),
                APPLOADER_PACKAGE_MAGIC_SIZE);

    auto elf = read_entire_file(elf_path);
    uint64_t elf_tl =
            htobe64((APPLOADER_RECORD_TYPE_ELF << APPLOADER_RECORD_TYPE_SHIFT) |
                    elf.size());
    write_to_fd(fd, reinterpret_cast<const uint8_t*>(&elf_tl), sizeof(elf_tl));
    write_to_fd(fd, reinterpret_cast<const uint8_t*>(elf.data()), elf.size());

    auto manifest = read_entire_file(manifest_path);
    uint64_t manifest_tl = htobe64(
            (APPLOADER_RECORD_TYPE_MANIFEST << APPLOADER_RECORD_TYPE_SHIFT) |
            manifest.size());
    write_to_fd(fd, reinterpret_cast<const uint8_t*>(&manifest_tl),
                sizeof(manifest_tl));
    write_to_fd(fd, reinterpret_cast<const uint8_t*>(manifest.data()),
                manifest.size());

    close(fd);
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

    default:
        print_usage_and_exit(argv[0], EXIT_FAILURE);
        break;
    }

    return 0;
}
