#!/usr/bin/env python

'''
This program will take truseted application's manifest config JSON file as
input. Processes the JSON config file and creates packed data
mapping to C structures and dumps in binary format.

USAGE:
    manifest_compiler.py --input <input_filename> --output <output_filename>

    Arguments:
    input_filename  - Trusted app manifest config file in JSON format.
    output_filename - Binary file containing packed manifest config data mapped
                      to C structres.

    example:
        manifest_compiler.py --input manifest.json --output output.bin

   Input sample JSON Manifest config file content -
   {
      "uuid": "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf",
      "min_heap": 4096,
      "min_stack": 4096
   }

   Output packed data:
   {
      { 16 bytes UUID }
      unsigned char uuid[16];

      { min_heap_tag, min_heap_value, min_stack_tag, min_stack_value }
      uint32_t configs[4];
   }
'''

import argparse
import cStringIO
import json
import optparse
import os.path
import struct
import sys


# Manifest properties
UUID = "uuid"
MIN_HEAP = "min_heap"
MIN_STACK = "min_stack"

# CONFIG TAGS
# These values need to be kept in sync with uapi/trusty_app_manifest_types.h
TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE = 1
TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE = 2


'''
Holds Manifest data to be used for packing
'''
class Manifest(object):
    def __init__(self, uuid, min_heap, min_stack):
        self.uuid = uuid
        self.min_heap = min_heap
        self.min_stack = min_stack


'''
Tracks errors during manifest compilation
'''
class Log(object):
    def __init__(self):
        self.error_count = 0

    def error(self, msg):
        sys.stderr.write("Error: {}\n".format(msg))
        self.error_count += 1

    def error_occurred(self):
        return self.error_count > 0


'''
Determines whether the value for the given key in dictionary is of type string
and if it is a string then returns the value.
'''
def get_string(manifest_dict, key, log):
    if key not in manifest_dict:
        log.error(
                "Manifest is missing required attribute - {} "
                .format(key))
        return None

    str_value = manifest_dict.pop(key)
    if not isinstance(str_value, str) and \
            not isinstance(str_value, unicode):
        log.error(
                "Invalid value for" +
                " {} - \"{}\", Valid string value is expected"
                .format(key, str_value))
        return None

    return str_value


'''
Determines whether the value for the given key in dictionary is of type integer
and if it is int then returns the value
'''
def get_int(manifest_dict, key, log):
    if key not in manifest_dict:
        log.error("Manifest is missing required attribute - {}".format(key))
        return None

    int_value = manifest_dict.pop(key)

    if isinstance(int_value, int):
        return int_value
    elif isinstance(int_value, basestring):
        try:
            return int(int_value, 0)
        except ValueError as ex:
            log.error("Invalid value for" +
                      " {} - \"{}\", valid integer or hex string is expected"
                      .format(key, int_value))
            return None
    else:
        log.error("Invalid value for" +
                  " {} - \"{}\", valid integer value is expected"
                  .format(key, int_value))
        return None

    return int_value


'''
Validate and arrange UUID byte order
If its valid UUID then returns 16 byte UUID
'''
def parse_uuid(uuid, log):
    if uuid is None:
        return None

    # Example UUID: "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
    if len(uuid) != 36:
        log.error(
                "Invalid UUID " +
                "{}, uuid should be of length 16 bytes of hex values"
                .format(uuid))
        return None

    uuid_data = uuid.split("-")
    if len(uuid_data) != 5:
        log.error(
                "Invalid UUID {}".format(uuid) +
                "uuid should be of length 16 bytes of hex divided into 5 groups"
                )
        return None

    try:
        uuid_data = [part.decode("hex") for part in uuid_data]
    except TypeError as ex:
        log.error("Invalid UUID {}, {}".format(uuid, ex))
        return None

    if len(uuid_data[0]) != 4 or \
            len(uuid_data[1]) != 2 or \
            len(uuid_data[2]) != 2 or \
            len(uuid_data[3]) != 2 or \
            len(uuid_data[4]) != 6:
        log.error("Wrong grouping of UUID - {}".format(uuid))
        return None

    return "".join(uuid_data)


'''
Validate memory size value.
if success return memory size value else return None
'''
def parse_memory_size(memory_size, log):
    if memory_size is None:
        return None

    if memory_size <= 0 or memory_size % 4096 != 0:
        log.error(
                "{}: {}, Minimum memory size should be "
                .format(MIN_STACK, memory_size) +
                "non-negative multiple of 4096")
        return None

    return memory_size


'''
validate the manifest config and extract key, values
'''
def parse_manifest_config(manifest_dict, log):
    # UUID
    uuid = parse_uuid(get_string(manifest_dict, UUID, log), log)

    # MIN_HEAP
    min_heap = parse_memory_size(get_int(manifest_dict, MIN_HEAP, log), log)

    # MIN_STACK
    min_stack = parse_memory_size(get_int(manifest_dict, MIN_STACK, log), log)

    # look for any extra attributes
    if manifest_dict:
        log.error("Unknown atributes in manifest: {} ".format(manifest_dict))

    if log.error_occurred():
        return None

    return Manifest(uuid, min_heap, min_stack)


'''
This script represents UUIDs in a purely big endian order.
Trusty stores the first three components of the UUID in little endian order.
Rearrange the byte order for Trusty.
'''
def pack_uuid(uuid):
    return uuid[3::-1] + uuid[5:3:-1] + uuid[7:5:-1] + uuid[8:]


'''
Creates Packed data from extracted manifest data
Writes the packed data to binary file
'''
def pack_manifest_data(manifest, log):
    # PACK {
    #        uuid,
    #        TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE, min_heap,
    #        TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE, min_stack
    #      }
    out = cStringIO.StringIO()

    uuid = pack_uuid(manifest.uuid)
    out.write(uuid)

    out.write(
            struct.pack("ii",
                        TRUSTY_APP_CONFIG_KEY_MIN_HEAP_SIZE,
                        manifest.min_heap))

    out.write(
            struct.pack("ii",
                        TRUSTY_APP_CONFIG_KEY_MIN_STACK_SIZE,
                        manifest.min_stack))

    return out.getvalue()


def write_packed_data_to_bin_file(packed_data, output_file, log):
    # Write packed data to binary file
    try:
        with open(output_file, "wb") as out_file:
            out_file.write(packed_data)
            out_file.close()
    except IOError as ex:
        log.error(
                "Unable to write to output file: {}"
                .format(output_file) + "\n" + str(ex))


def read_manifest_config_file(input_file, log):
    try:
       read_file = open(input_file, "r")
    except IOError as ex:
        log.error(
                "Unable to open input file: {}"
                .format(input_file) + "\n" + str(ex))
        return None

    try:
        manifest_dict = json.load(read_file)
        return manifest_dict
    except ValueError as ex:
        log.error(
                "Unable to parse manifest config JSON - {}"
                .format(str(ex)))
        return None


'''
START OF THE PROGRAM
Handles the command line arguments
Parses the given manifest input file and creates packed data
Writes the packed data to binary output file.
'''
def main(argv):
    parser = argparse.ArgumentParser();
    parser.add_argument(
            "-i", "--input",
            dest="input_filename",
            required=True,
            type=str,
            help="It should be trust app manifest config JSON file"
    )
    parser.add_argument(
            "-o", "--output",
            dest="output_filename",
            required=True,
            type=str,
            help="It will be binary file with packed manifest data"
    )
    # Parse the command line arguments
    args = parser.parse_args()

    log = Log()

    if not os.path.exists(args.input_filename):
        log.error(
                "Manifest config JSON file doesn't exist: {}"
                .format(args.input_filename))
        return 1

    manifest_dict = read_manifest_config_file(args.input_filename, log)
    if log.error_occurred():
        return 1

    # parse the manifest config
    manifest = parse_manifest_config(manifest_dict, log)
    if log.error_occurred():
        return 1

    # Pack the data as per c structures
    packed_data = pack_manifest_data(manifest, log)
    if log.error_occurred():
        return 1

    # Write to file.
    write_packed_data_to_bin_file(packed_data, args.output_filename, log)
    if log.error_occurred():
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
