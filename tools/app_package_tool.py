#!/usr/bin/env python2.7

import argparse
import os
import struct
import sys

class Record:
    # Record types
    TYPE_ELF = 0
    TYPE_MANIFEST = 1

    # The type-length field is encoded in network order on disk; readers need
    # to convert it to host encoding manually
    _TYPE_LENGTH_FORMAT = '!Q'

    # The type-length field consists of the following:
    #  - type field: 16 most significant bits
    #  - length field: 48 least significant bits
    _TYPE_SHIFT = 48

    def __init__(self, record_type, payload=[]):
        self.record_type = record_type
        self.payload = payload

    @staticmethod
    def read(f, pos=None):
        tl_len = struct.calcsize(Record._TYPE_LENGTH_FORMAT)
        tl_bytes = f.read(tl_len)
        if len(tl_bytes) < tl_len:
            return None

        tl = struct.unpack(Record._TYPE_LENGTH_FORMAT, tl_bytes)[0]
        ty = tl >> Record._TYPE_SHIFT
        length = tl ^ (ty << Record._TYPE_SHIFT)
        payload = f.read(length)
        if len(payload) < length:
            return None

        return Record(ty, payload)

    def write(self, f, pos=None):
        assert (len(self.payload) >> Record._TYPE_SHIFT) == 0, "Payload too big"
        tl = (self.record_type << Record._TYPE_SHIFT) | len(self.payload)
        f.write(struct.pack(Record._TYPE_LENGTH_FORMAT, tl))
        f.write(self.payload)


class Package:
    _HEADER_MAGIC = b'TrustyAp'

    def __init__(self, records=[]):
        self.records = records

    @staticmethod
    def read(f):
        magic = f.read(len(Package._HEADER_MAGIC))
        if magic != Package._HEADER_MAGIC:
            return None

        records = []
        while True:
            record = Record.read(f)
            if record is None:
                return Package(records)

            records.append(record)

    def write(self, f):
        f.write(Package._HEADER_MAGIC)
        for record in self.records:
            record.write(f)


def build_package(args):
    elf_record = Record(Record.TYPE_ELF)
    with open(args.elf, 'rb') as input_file:
        elf_record.payload = input_file.read()

    manifest_record = Record(Record.TYPE_MANIFEST)
    with open(args.manifest, 'rb') as input_file:
        manifest_record.payload = input_file.read()

    # Package file contents:
    #   u64 package_magic
    #   ELF file record
    #     u16 type = APPLOADER_RECORD_TYPE_ELF
    #     u48 length
    #     byte record[length]
    #   Manifest file record
    #     u16 type = APPLOADER_RECORD_TYPE_MANIFEST
    #     u48 length
    #     byte record[length]
    #
    #   There is no alignment requirement for any record, and no padding
    #   before or after each record
    package = Package([elf_record, manifest_record])
    with open(args.package, 'wb') as package_file:
        package.write(package_file)

    return 0


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_build = subparsers.add_parser('build',
            help='build an application package from an ELF file and a manifest')
    parser_build.add_argument('package',
            help='path to the package file to generate')
    parser_build.add_argument('elf',
            help='path to the input ELF file')
    parser_build.add_argument('manifest',
            help='path to the input manifest file')
    parser_build.set_defaults(func=build_package)

    # Parse the command line arguments
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
