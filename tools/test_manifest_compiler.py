#!/usr/bin/env python

'''
Command to run tests:
  python2 -m unittest -v test_manifest_compiler
'''

import unittest
import os
import struct

import manifest_compiler

class TestManifest(unittest.TestCase):
    '''
    Test with integer value as input to get_string
    '''
    def test_get_string_1(self):
        log = manifest_compiler.Log()
        config_data  = {"data": 1234}
        data = manifest_compiler.get_string(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with valid uuid value as input to get_string
    '''
    def test_get_string_2(self):
        log = manifest_compiler.Log()
        uuid = "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
        config_data  = {"data": uuid}
        data = manifest_compiler.get_string(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, uuid)

    '''
    Test with empty string
    '''
    def test_get_string_3(self):
        log = manifest_compiler.Log()
        config_data  = {"data": ""}
        data = manifest_compiler.get_string(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, "")

    '''
    Test with empty config data
    '''
    def test_get_string_4(self):
        log = manifest_compiler.Log()
        config_data  = {}
        data = manifest_compiler.get_string(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with empty string for get_int
    '''
    def test_get_int_1(self):
        log = manifest_compiler.Log()
        config_data  = {"data": ""}
        data = manifest_compiler.get_int(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with string of integers
    '''
    def test_get_int_2(self):
        log = manifest_compiler.Log()
        config_data  = {"data": "4096"}
        data = manifest_compiler.get_int(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with integer value
    '''
    def test_get_int_3(self):
        log = manifest_compiler.Log()
        config_data  = {"data": 4096}
        data = manifest_compiler.get_int(config_data, "data", log)
        self.assertEqual(len(config_data), 0)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, 4096)

    '''
    Test with empty config data
    '''
    def test_get_int_4(self):
        log = manifest_compiler.Log()
        config_data  = {}
        data = manifest_compiler.get_int(config_data, "data", log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with valid UUID with hex values
    '''
    def test_validate_uuid_1(self):
        log = manifest_compiler.Log()
        uuid_in = "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
        data = manifest_compiler.parse_uuid(uuid_in, log)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data.encode("hex"), uuid_in.replace("-", ""))

    '''
    Test with invalid UUID containing one byte less
    '''
    def test_validate_uuid_2(self):
        log = manifest_compiler.Log()
        uuid  = "902ace-5e5c-4cd8-ae54-87b88c22ddaf"
        data = manifest_compiler.parse_uuid(uuid, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid number of bytes in uuid groups
    '''
    def test_validate_uuid_3(self):
        log = manifest_compiler.Log()
        uuid  = "5f902ace5e-5c-4cd8-ae54-87b88c22ddaf"
        data = manifest_compiler.parse_uuid(uuid, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with valid UUID value but ungrouped
    '''
    def test_validate_uuid_6(self):
        log = manifest_compiler.Log()
        uuid  = "5f902ace5e5c4cd8ae5487b88c22ddaf"
        data = manifest_compiler.parse_uuid(uuid, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid UUID value
    '''
    def test_validate_uuid_7(self):
        log = manifest_compiler.Log()
        uuid  = "12345678-9111-1222-3333-222111233222"
        data = manifest_compiler.parse_uuid(uuid, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid UUID value
    '''
    def test_validate_uuid_7(self):
        log = manifest_compiler.Log()
        uuid  = ""
        data = manifest_compiler.parse_uuid(uuid, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with valid memory size
    '''
    def test_validate_memory_size_1(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(4096, log)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, 4096)

    '''
    Test with valid memory size
    '''
    def test_validate_memory_size_2(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(8192, log)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, 8192)

    '''
    Test with invalid memory size
    '''
    def test_validate_memory_size_3(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(0, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid memory size
    '''
    def test_validate_memory_size_4(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(-4096, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid memory size
    '''
    def test_validate_memory_size_5(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(4095, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid memory size
    '''
    def test_validate_memory_size_6(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(16777217, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with invalid memory size
    '''
    def test_validate_memory_size_7(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(1024, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(data)

    '''
    Test with valid large integer value (2**32) as memory size
    '''
    def test_validate_memory_size_8(self):
        log = manifest_compiler.Log()
        data = manifest_compiler.parse_memory_size(4294967296, log)
        self.assertFalse(log.error_occurred())
        self.assertEqual(data, 4294967296)

    '''
    Test with valid UUID with hex values and
    valid values for min_heap and min_stack.
    '''
    def test_manifest_valid_dict_1(self):
        uuid_in = "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
        min_heap = 4096
        min_stack = 4096
        log = manifest_compiler.Log()

        config_data  = {
                "uuid": uuid_in,
                "min_heap": min_heap,
                "min_stack": min_stack
        }
        manifest = manifest_compiler.parse_manifest_config(config_data, log)
        self.assertFalse(log.error_occurred())
        self.assertIsNotNone(manifest)
        self.assertEqual(manifest.uuid.encode("hex"), uuid_in.replace("-", ""))
        self.assertEqual(manifest.min_heap, min_heap)
        self.assertEqual(manifest.min_stack, min_stack)

    '''
    Test with invalid value in config,
    UUID with integer value and string values for min_stack.
    '''
    def test_manifest_invalid_dict_2(self):
        log = manifest_compiler.Log()
        config_data  = {"uuid": 123, "min_heap": "4096", "min_stack": "8192"}
        manifest = manifest_compiler.parse_manifest_config(config_data, log)
        self.assertEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(manifest)

    '''
    Test with empty config.
    '''
    def test_manifest_invalid_dict_3(self):
        log = manifest_compiler.Log()
        config_data  = {}
        manifest = manifest_compiler.parse_manifest_config(config_data, log)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(manifest)

    '''
    Test with unknown entries
    '''
    def test_manifest_invalid_dict_4(self):
        log = manifest_compiler.Log()
        config_data  = {"uuid": "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf",
                         "min_heap": 4096, "min_stack": 4096, "max_heap": 234}
        manifest = manifest_compiler.parse_manifest_config(config_data, log)
        self.assertNotEqual(len(config_data), 0)
        self.assertTrue(log.error_occurred())
        self.assertIsNone(manifest)

    '''
    Test with valid UUID with hex values and
    valid values for min_heap and min_stack.
    Pack the manifest config data and unpack it and
    verify it with the expected values
    '''
    def test_manifest_valid_pack_1(self):
        # PLZ DON'T EDIT VALUES
        uuid_in = "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
        uuid_out = "ce2a905f5c5ed84cae5487b88c22ddaf"
        min_heap = 8192
        min_stack = 4096
        log = manifest_compiler.Log()

        config_data  = {
                "uuid": uuid_in,
                "min_heap": min_heap,
                "min_stack": min_stack
        }

        manifest = manifest_compiler.parse_manifest_config(config_data, log)
        self.assertFalse(log.error_occurred())
        packed_data = manifest_compiler.pack_manifest_data(manifest, log)
        self.assertEqual(len(config_data), 0)
        self.assertFalse(log.error_occurred())
        self.assertIsNotNone(packed_data)

        uuid, packed_data = packed_data[:16], packed_data[16:]
        self.assertEqual(uuid.encode("hex"), uuid_out)

        (tag1,), packed_data = struct.unpack(
                "I", packed_data[:4]), packed_data[4:]
        self.assertEqual(tag1, 2)

        (value1,), packed_data = struct.unpack(
                "I", packed_data[:4]), packed_data[4:]
        self.assertEqual(value1, 8192)

        (tag2,), packed_data = struct.unpack(
                "I", packed_data[:4]), packed_data[4:]
        self.assertEqual(tag2, 1)

        (value2,), packed_data = struct.unpack(
                "I", packed_data[:4]), packed_data[4:]
        self.assertEqual(value2, 4096)


'''
START - Test start point
'''
if __name__ == "__main__":
    unittest.main()
