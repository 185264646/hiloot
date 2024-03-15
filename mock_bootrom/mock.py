#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# A mock HiSilicon BootROM serial boot implementation
# Copyright 2024 (c) Yang Xiwen

from enum import Enum, auto
import logging
from typing import Set

from binascii import crc_hqx

import serial

from serial.serialutil import Timeout

from hiloot import ChipID, Frame

# TODO: Find all possible cmds for each stage
class HiSTBBootROMState(Enum):
    """All possible state of HiSTB BootROM DFA"""
    POWER_DOWN = auto()
    BOOTROM_START = auto()
    # Output power on message and delay for a while
    WAIT_TYPE_FRAME = auto()
    # Wait for a type frame for about 0.5 seconds, continue normal boot if timeout
    WAIT_HEAD_AREA = auto()
    # Wait for head area, can also process type frame
    WAIT_AUXCODE_AREA = auto()
    # Wait for auxcode area
    WAIT_EXTRA_AREA = auto()
    # Wait for extra area
    WAIT_ASC_AREA = auto()
    # Wait for ACPU code
    WAIT_FASTBOOT_IMAGE = auto()
    # Wait for fastboot image
    DONE = auto()
    ERROR = auto()

PredefinedChipID = {
        'MV200': ChipID(0x37986200, 0x3, False, False, False),
        }

class FrameInfo(NamedTuple):
    start_byte: bytes
    length: int

class FrameInfoEnums(Enum):
    # start_byte, length
    TYPE = FrameInfo(b'\xbd', 13)
    HEAD = FrameInfo(b'\xfe', 13)
    DATA = FrameInfo(b'\xda', 1029)
    TAIL = FrameInfo(b'\xed', 13)
    BOARD = FrameInfo(b'\xce', 13)

    @classmethod
    def get_from_byte(cls, b: bytes):
        for i in cls:
            if i.start_byte == b:
                return i
        raise ValueError("f{b} not found")


class HiSTBBootROM:
    BOOTROM_START_MSG = "\r\nBootrom start\r\nBoot Media: eMMC\r\n"
    AUX_CODE_MSG = """
Decrypt auxiliary code ...OK

lsadc voltage min: 000000FE, max: 000000FF, aver: 000000FE, index: 00000000

Entry boot auxiliary code

Auxiliary code - v1.00
DDR code - V1.1.2 20160205
Build: Mar 24 2016 - 17:09:44
Reg Version:  v134
Reg Time:     2016/03/18 09:44:55
Reg Name:     hi3798cv2dmb_hi3798cv200_ddr3_2gbyte_8bitx4_4layers.reg
"""
    EXIT_MSG = "\r\nBoot auxiliary code success\r\nBootrom success\r\n"

    def __init__(self, dev: serial.Serial, chipid: ChipID):
        self.state = HiSTBBootROMState.POWER_DOWN
        self.dev = dev
        self.chipid = chipid
        self.timeout = False

    def _read_until(self, start_bytes: Set[bytes]) -> bytes:
        """
        An enhanced version of read_until which supports multiple start_byte
        """
        timeout = Timeout(self.dev.timeout)
        res = bytearray()

        while not timeout.expired():
            ch = self.dev.read(1)
            if ch:
                res.append(ch[0])
            else:
                break

        return bytes(res)

    def _read_packet(self, allowed_frames: Set[FrameInfo]) -> Frame:
        """
        Read a packet from host

        :param start_bytes: expected start byte of the packet
        :param length: packet length
        :raises TimeoutError: timeout
        :raises ValueError: checksum error
        :returns: retrived frame
        """
        start_bytes = map(lambda frame: frame.start_byte, allowed_frames)
        msg = self._read_until(start_bytes)
        if not any(map(msg.endswith, start_bytes)):
            logging.error("start_byte not found till timeout")
            raise TimeoutError
        elif len(msg) > 1:
            logging.warning("Garbage found. This might lead to some problems for real hardware")
            logging.info("garbage hex: %s", msg[:-1].hex())
        length = FrameInfoEnums.get_from_byte(msg[-1:])
        pkt = msg[-1:] + self.dev.read(length - 1)
        if len(pkt) != length:
            raise TimeoutError
        return Frame.from_bytes(pkt, True)

    def communicate(self, start_bytes: Set[bytes], length: int) -> Frame:
        """
        Read a packet from host, echo checksum status, auto restart till timeout
        """
        try:
            pkt = self._read_packet(start_bytes, length)
        except ValueError:
            # Retry if the frame is broken
            self.dev.write(b'\x55')
            pkt = self._read_packet_retry(start_bytes, length)

        self.dev.write(b'\xAA')
        return pkt

    def serve_once(self):
        if self.state == HiSTBBootROMState.POWER_DOWN:
            pass
        elif self.state == HiSTBBootROMState.BOOTROM_START:
            time.sleep(.5)
            self.dev.write(b"BootROM Start\r\nBootMedia: eMMC\r\n")
            self._timer = Timeout(.5)
            self.state += 1
        elif self.state == HiSTBBootROMState.WAIT_TYPE_FRAME:
            if self._timer.expired():
                # No type frame is found before timeout
                self.state = HiSTBBootROMState.ERROR
            else:
                self.communicate((b'\xbd', b'\xfe'), 


        elif self.state == HiSTBBootROMState.WAIT_HEAD_AREA:
            ...

    def start_loop(self):
        self.state = HiSTBBootROMState.BOOTROM_START
        while not self.state in (HiSTBBootROMState.DONE, HiSTBBootROMState.ERROR):
            self.serve_once()

