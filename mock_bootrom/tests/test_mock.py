import unittest

import serial

from hiloot import Frame, FrameType
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

    def test_read_packet(self):
        test_frame_okay = Frame(FrameType.TYPE, 0x78, b'test')
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        recv_pkt = self.obj._read_packet((b'\xbd',), 9)
        self.assertEqual(recv_pkt, test_frame_okay)

        # prepend some garbage
        self.obj.dev.write(b'garbage')
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        recv_pkt = self.obj._read_packet((b'\xbd',), 9)
        self.assertEqual(recv_pkt, test_frame_okay)

        # insufficient frame
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        with self.assertRaises(TimeoutError):
            self.obj._read_packet((b'\xbd',), 10)

        # checksum mismatch
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        with self.assertRaises(ValueError):
            self.obj._read_packet((b'\xbd',), 8)

