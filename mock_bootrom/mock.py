#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# A mock HiSilicon BootROM serial boot implementation
# Copyright 2024 (c) Yang Xiwen

from enum import Enum, auto
import logging
from typing import Callable, Dict, Optional, Set

from binascii import crc_hqx

import serial

from serial.serialutil import Timeout

from hiloot import ChipID, HeadRequest, Frame, FrameType

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

class FrameInfoEnums(bytes, Enum):
    # start_byte, length
    TYPE = (b'\xbd', 14)
    HEAD = (b'\xfe', 14)
    DATA = (b'\xda', 1029)
    TAIL = (b'\xed', 5)
    BOARD = (b'\xce', 14)

    def __new__(cls, start_byte: bytes, length: int):
        obj = bytes.__new__(cls, start_byte)
        obj._value_ = start_byte
        obj.length = length
        return obj

    @property
    def as_tuple(self):
        return (self._value_, self.length)

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
                if ch in start_bytes:
                    break
            else:
                break

        return bytes(res)

    def _read_packet(self, allowed_frames: Dict[bytes, int]) -> Frame:
        """
        Read a packet from host

        :param allowed_frames: expected start byte and packet length
        :raises TimeoutError: timeout
        :raises ValueError: checksum error
        :returns: retrived frame
        """
        start_bytes = allowed_frames.keys()
        msg = self._read_until(start_bytes)
        if not any(map(msg.endswith, start_bytes)):
            logging.warning("start_byte not found till timeout, received msg hex: %s", msg.hex())
            raise TimeoutError
        elif len(msg) > 1:
            logging.warning("Garbage found. This might lead to some problems for real hardware")
            logging.info("garbage hex: %s", msg[:-1].hex())
        length = allowed_frames[msg[-1:]]
        pkt = msg[-1:] + self.dev.read(length - 1)
        if len(pkt) != length:
            raise TimeoutError
        return Frame.from_bytes(pkt, True)

    def communicate(self, allowed_frames: Dict[bytes, int], get_reply: Optional[Callable[[bytes], bytes]] = None) -> Frame:
        """
        Read a packet from host, auto restart if checksum mismatch
        """
        while True:
            try:
                pkt = self._read_packet(allowed_frames)
            except ValueError:
                logging.warning("CRC mismatch, retrying...")
                self.dev.write(b'\x55')
                continue
            if get_reply:
                reply = get_reply(pkt)
            else:
                reply = b'\xAA'
            self.dev.write(reply)
            if reply != b'\x55':
                break

        return pkt

    def answer_type_frame(self, timeout: False) -> None:
        """
        read and answer type frame from host
        """
        ...

    def retrive_file(self, skip_head = False, total = 2) -> None:
        """
        Read a file from host

        :param skip_head: skip head packet (HACK)
        :param total: if head packet is skipped, specify total data packets
        """
        current_index = 1 if skip_head else 0

        def validate_file_packet(frame: Frame) -> bool:
            nonlocal current_index, total
            if current_index == 0:
                # HEAD frame is not received.
                if frame.type != FrameType.HEAD:
                    return False
                hdr = HeadRequest.from_bytes(frame.payload)
                total = 1 + (hdr.size + 1023) // 1024
                current_index += 1
                return True
            elif current_index == 1:
                # HEAD received, but the host may still duplicate HEAD frame
                if frame.type not in (FrameType.HEAD, FrameType.DATA):
                    return False
                elif frame.seq != 1:
                    return False
                current_index += 1
                return True
            elif 1 < current_index < total:
                if frame.type != FrameType.DATA:
                    return False
                elif frame.seq not in (current_index % 256, (current_index - 1) % 256):
                    return False
                current_index += 1
                return True
            elif current_index == total:
                if frame.type not in (FrameType.DATA, FrameType.TAIL):
                    return False
                elif frame.type == FrameType.TAIL:
                    current_index += 1
                    return True
                elif frame.seq != current_index % 256:
                    return False
                return True
            return False

        while current_index <= total:
            if current_index == 0:
                allowed_frames = dict((FrameInfoEnums.HEAD.as_tuple,))
            elif current_index == 1:
                allowed_frames = dict((FrameInfoEnums.HEAD.as_tuple, FrameInfoEnums.DATA.as_tuple))
            elif 1 < current_index < total:
                allowed_frames = dict((FrameInfoEnums.DATA.as_tuple,))
            else:
                allowed_frames = dict((FrameInfoEnums.DATA.as_tuple, FrameInfoEnums.TAIL.as_tuple))

            self.communicate(allowed_frames, lambda pkt: b'\xAA' if validate_file_packet(pkt) else b'\x55')


    def serve_once(self):
        if self.state == HiSTBBootROMState.POWER_DOWN:
            pass
        elif self.state == HiSTBBootROMState.BOOTROM_START:
            time.sleep(.5)
            self.dev.write(self.BOOTROM_START_MSG)
            self._timer = Timeout(.5)
            self.state += 1
        elif self.state == HiSTBBootROMState.WAIT_TYPE_FRAME:
            if self._timer.expired():
                # No type frame is found before timeout
                self.state = HiSTBBootROMState.ERROR
            else:
                try:
                    # FIXME: retrieve chip id from framework
                    self.communicate(dict((FrameInfoEnums.TYPE,)), b'\xBD\x00\xFF\x08\x00\x00\x00\x37\x98\x03\x00\xAA')
                except TimeoutError:
                    pass
                else:
                    self.state += 1
        elif self.state == HiSTBBootROMState.WAIT_HEAD_AREA:
            ...

    def start_loop(self):
        self.state = HiSTBBootROMState.BOOTROM_START
        while not self.state in (HiSTBBootROMState.DONE, HiSTBBootROMState.ERROR):
            self.serve_once()

