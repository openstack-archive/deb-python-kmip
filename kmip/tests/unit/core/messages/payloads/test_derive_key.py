# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import testtools

from kmip.core import attributes
from kmip.core import enums
from kmip.core import objects
from kmip.core import utils

from kmip.core.messages.payloads import derive_key


class TestDeriveKeyRequestPayload(testtools.TestCase):
    """
    Test suite for the DeriveKey request payload.
    """

    def setUp(self):
        super(TestDeriveKeyRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document. The
        # rest of the encoding is a manual construction, since DeriveKey is
        # not specifically detailed by the testing document.
        #
        # This encoding matches the following set of values:
        # Object Type - SymmetricKey
        # Unique Identifiers
        #     fb4b5b9c-6188-4c63-8142-fe9c328129fc
        #     5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3
        #     1703250b-4d40-4de2-93a0-c494a1d4ae40
        # Derivation Method - HMAC
        # Derivation Parameters
        #     Cryptographic Parameters
        #         Hashing Algorithm - SHA-256
        #     Initialization Vector - 0x39487432492834A3
        #     Derivation Data - 0xFAD98B6ACA6D87DD
        # Template Attribute
        #     Attribute
        #         Attribute Name - Cryptographic Algorithm
        #         Attribute Value - AES
        #     Attribute
        #         Attribute Name - Cryptographic Length
        #         Attribute Value - 128

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x68'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x66\x62\x34\x62\x35\x62\x39\x63'
            b'\x2D\x36\x31\x38\x38\x2D\x34\x63\x36\x33\x2D\x38\x31\x34\x32\x2D'
            b'\x66\x65\x39\x63\x33\x32\x38\x31\x32\x39\x66\x63\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x35\x63\x39\x62\x38\x31\x65\x66'
            b'\x2D\x34\x65\x65\x35\x2D\x34\x32\x63\x64\x2D\x62\x61\x32\x64\x2D'
            b'\x63\x30\x30\x32\x66\x64\x64\x30\x63\x37\x62\x33\x00\x00\x00\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24\x31\x37\x30\x33\x32\x35\x30\x62'
            b'\x2D\x34\x64\x34\x30\x2D\x34\x64\x65\x32\x2D\x39\x33\x61\x30\x2D'
            b'\x63\x34\x39\x34\x61\x31\x64\x34\x61\x65\x34\x30\x00\x00\x00\x00'
            b'\x42\x00\x31\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x32\x01\x00\x00\x00\x38'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x3A\x08\x00\x00\x00\x08\x39\x48\x74\x32\x49\x28\x34\xA3'
            b'\x42\x00\x30\x08\x00\x00\x00\x08\xFA\xD9\x8B\x6A\xCA\x6D\x87\xDD'
            b'\x42\x00\x91\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x41\x6C\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14\x43\x72\x79\x70\x74\x6F\x67\x72'
            b'\x61\x70\x68\x69\x63\x20\x4C\x65\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDeriveKeyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a DeriveKey request payload can be constructed with no
        arguments.
        """
        payload = derive_key.DeriveKeyRequestPayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifiers)
        self.assertEqual(None, payload.derivation_method)
        self.assertEqual(None, payload.derivation_parameters)
        self.assertEqual(None, payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a DeriveKey request payload can be constructed with valid
        values
        """
        payload = derive_key.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['00000000-1111-2222-3333-444444444444'],
            derivation_method=enums.DerivationMethod.HASH,
            derivation_parameters=attributes.DerivationParameters(),
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            enums.ObjectType.SYMMETRIC_KEY,
            payload.object_type
        )
        self.assertEqual(
            ['00000000-1111-2222-3333-444444444444'],
            payload.unique_identifiers
        )
        self.assertEqual(
            enums.DerivationMethod.HASH,
            payload.derivation_method
        )
        self.assertEqual(
            attributes.DerivationParameters(),
            payload.derivation_parameters
        )
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_object_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object type of a DeriveKey request payload.
        """
        payload = derive_key.DeriveKeyRequestPayload()
        args = (payload, 'object_type', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "object type must be an ObjectType enumeration",
            setattr,
            *args
        )

    def test_invalid_unique_identifiers(self):
        """
        Test that a TypeError is raised when invalid values are used to set
        the unique identifiers of a DeriveKey request payload.
        """
        payload = derive_key.DeriveKeyRequestPayload()
        args = (payload, 'unique_identifiers', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "unique identifiers must be a list of strings",
            setattr,
            *args
        )

        args = (payload, 'unique_identifiers', [0])
        self.assertRaisesRegexp(
            TypeError,
            "unique identifiers must be a list of strings",
            setattr,
            *args
        )

        args = (payload, 'unique_identifiers', ['valid', 'valid', 0])
        self.assertRaisesRegexp(
            TypeError,
            "unique identifiers must be a list of strings",
            setattr,
            *args
        )

    def test_invalid_derivation_method(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the derivation method of a DeriveKey request payload.
        """
        payload = derive_key.DeriveKeyRequestPayload()
        args = (payload, 'derivation_method', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "derivation method must be a DerivationMethod enumeration",
            setattr,
            *args
        )

    def test_invalid_derivation_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the derivation parameters of a DeriveKey request payload.
        """
        payload = derive_key.DeriveKeyRequestPayload()
        args = (payload, 'derivation_parameters', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "derivation parameters must be a DerivationParameters struct",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a DeriveKey request payload.
        """
        payload = derive_key.DeriveKeyRequestPayload()
        args = (payload, 'template_attribute', 'invalid')
        self.assertRaisesRegexp(
            TypeError,
            "template attribute must be a TemplateAttribute struct",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeriveKey request payload can be read from a data stream.
        """
        payload = derive_key.DeriveKeyRequestPayload()

        self.assertEqual(None, payload.object_type)
        self.assertEqual(None, payload.unique_identifiers)
        self.assertEqual(None, payload.derivation_method)
        self.assertEqual(None, payload.derivation_parameters)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.full_encoding)

    def test_read_missing_object_type(self):
        self.skip('')

    def test_read_missing_unique_identifiers(self):
        self.skip('')

    def test_read_missing_derivation_method(self):
        self.skip('')

    def test_read_missing_derivation_parameters(self):
        self.skip('')

    def test_read_missing_template_attribute(self):
        self.skip('')

    def test_write(self):
        self.skip('')

    def test_write_missing_object_type(self):
        self.skip('')

    def test_write_missing_unique_identifiers(self):
        self.skip('')

    def test_write_missing_derivation_method(self):
        self.skip('')

    def test_write_missing_derivation_parameters(self):
        self.skip('')

    def test_write_missing_template_attribute(self):
        self.skip('')

    def test_equal_on_equal(self):
        self.skip('')

    def test_equal_on_not_equal_object_type(self):
        self.skip('')

    def test_equal_on_not_equal_unique_identifiers(self):
        self.skip('')

    def test_equal_on_not_equal_derivation_method(self):
        self.skip('')

    def test_equal_on_not_equal_derivation_parameters(self):
        self.skip('')

    def test_equal_on_not_equal_template_attribute(self):
        self.skip('')

    def test_equal_on_type_mismatch(self):
        self.skip('')

    def test_not_equal_on_equal(self):
        self.skip('')

    def test_not_equal_on_not_equal_object_type(self):
        self.skip('')

    def test_not_equal_on_not_equal_unique_identifiers(self):
        self.skip('')

    def test_not_equal_on_not_equal_derivation_method(self):
        self.skip('')

    def test_not_equal_on_not_equal_derivation_parameters(self):
        self.skip('')

    def test_not_equal_on_not_equal_template_attribute(self):
        self.skip('')

    def test_not_equal_on_type_mismatch(self):
        self.skip('')

    def test_repr(self):
        self.skip('')

    def test_str(self):
        self.skip('')
