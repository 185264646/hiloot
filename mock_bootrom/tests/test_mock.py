import unittest

import serial

from ..mock import *

class TestHiSTBBootROM(unittest.TestCase):
    def setUp(self):
        loop_ser = serial.serial_for_url("loop://", timeout = .1)
        self.obj = HiSTBBootROM(loop_ser, PredefinedChipID['MV200'])

    def tearDown(self):
        pass

    def test_read_until(self):
        self.obj.dev.write(b'test_string')
        pkt = self.obj._read_until((b'r', b'_'))
        self.assertEqual(pkt, b'test_')
        # non-existant
        pkt = self.obj._read_until((b'#',))
        self.assertEqual(pkt, b'string')
