import logging
import os
import pty
import unittest
import time

import serial

from hiloot import Frame, FrameType, HeadRequest
from ..mock import *

class TestHiSTBBootROM(unittest.TestCase):
    def setUp(self):
        loop_ser = serial.serial_for_url("loop://", timeout = .1)
        self.obj = HiSTBBootROM(loop_ser, PredefinedChipID['MV200'])

        # for complex tests, loop_ser can not be used
        # use pty instead, it's bidirectional
        self.master, slave = pty.openpty()
        self.obj2 = HiSTBBootROM(serial.Serial(os.ttyname(slave), timeout = .2), PredefinedChipID['MV200'])
        logging.basicConfig(level = logging.ERROR)

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
        recv_pkt = self.obj._read_packet({b'\xbd': 9})
        self.assertEqual(recv_pkt, test_frame_okay)

        # prepend some garbage
        self.obj.dev.write(b'garbage')
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        recv_pkt = self.obj._read_packet({b'\xbd': 9})
        self.assertEqual(recv_pkt, test_frame_okay)

        # insufficient frame
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        with self.assertRaises(TimeoutError):
            self.obj._read_packet({b'\xbd': 10})

        # checksum mismatch
        self.obj.dev.write(test_frame_okay.to_bytes(True))
        with self.assertRaises(ValueError):
            self.obj._read_packet({b'\xbd': 8})

    def test_communicate(self):
        test_frame_okay = Frame(FrameType.TYPE, 0x78, b'test')
        os.write(self.master, test_frame_okay.to_bytes(True))
        recv_pkt = self.obj2.communicate({b'\xbd': 9})
        self.assertEqual(recv_pkt, test_frame_okay)
        # master fd may not get ready yet, so read_all() may fail
        out = os.read(self.master, 1)
        self.assertEqual(out, b'\xAA')

        os.write(self.master, test_frame_okay.to_bytes(True))
        with self.assertRaises(TimeoutError):
            self.obj2.communicate({b'\xbd': 8})

        out = os.read(self.master, 1)
        self.assertEqual(out, b'\x55')

        os.write(self.master, test_frame_okay.to_bytes(False))
        os.write(self.master, b'\x12\x34')
        os.write(self.master, test_frame_okay.to_bytes(True))
        recv_pkt = self.obj2.communicate({b'\xbd': 9})
        self.assertEqual(recv_pkt, test_frame_okay)
        out = os.read(self.master, 2)
        self.assertEqual(out, b'\x55\xAA')

    def test_retrive_file(self):
        file_size = 0x1000
        data_pkt_cnt = file_size // 0x400
        head_frame = Frame(FrameType.HEAD, 0, bytes(HeadRequest(file_size, 0x0)))
        data_frames = [Frame(FrameType.DATA, i, bytes(1024)) for i in range(1, data_pkt_cnt + 1)]
        tail_frame = Frame(FrameType.TAIL, data_pkt_cnt + 1, b'')

        os.write(self.master, head_frame.to_bytes(True))
        for frame in data_frames:
            os.write(self.master, frame.to_bytes(True))
        os.write(self.master, tail_frame.to_bytes(True))

        self.obj2.retrive_file()
        # FIXME: read in a loop, this is really unreliable
        # Wait for OS pty data sync
        time.sleep(.01)
        out = os.read(self.master, data_pkt_cnt + 2)
        self.assertEqual(out, b'\xAA' * (data_pkt_cnt + 2))

        os.write(self.master, head_frame.to_bytes(True))
        for frame in data_frames:
            # Mangle pkt 4
            os.write(self.master, frame.to_bytes(True if frame.seq != 4 else False))
            if frame.seq == 4:
                os.write(self.master, b'\x12\x34')
                os.write(self.master, frame.to_bytes(True))
        os.write(self.master, tail_frame.to_bytes(True))

        self.obj2.retrive_file()
        # FIXME: read in a loop, this is really unreliable
        time.sleep(.01)
        out=os.read(self.master, data_pkt_cnt + 3)
        self.assertEqual(out, b'\xAA' * data_pkt_cnt + b'\x55' + b'\xAA' * 2)

