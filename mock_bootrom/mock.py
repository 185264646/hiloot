#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# A mock HiSilicon BootROM serial boot implementation
# Copyright 2024 (c) Yang Xiwen

from enum import Enum, auto
from threading import Timer
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
            if not ch or ch in start_bytes:
                break

        return bytes(res)

    def _read_packet(self, start_bytes: Set[bytes], length: int, retry_on_crc_mismatch = True) -> Frame:
        """
        Read a packet from host and echo checksum status

        :param start_bytes: expected start byte of the packet
        :param length: packet length
        :param retry_on_crc_mismatch: retry if crc mismatch
        :raises RuntimeError: checksum error
        :raises TimeoutError: timeout
        :returns: retrived frame
        """
        msg = self.dev._read_until(start_bytes)
        if not any(map(msg.endswith, start_bytes)):
            logging.error("start_byte not found till timeout")
            raise TimeoutError
        elif len(hdr) > 1:
            logging.warning("Garbage found, this might lead to some problems for real hardware")
            logging.info("garbage hex: %s", hdr[:-1].hex())
        pkt = hdr[-1:] + self.dev.read(length - 1)
        if len(pkt) != length:
            raise TimeoutError
        try:
            frame = Frame.from_bytes(pkt)
        except ValueError:
            # Checksum mismatch
            self.dev.write(b'\x55')
            if retry_on_error:
                return self._read_packet(start_bytes, length, retry_on_error)
            raise RuntimeError("CRC mismatch")
        else:
            self.dev.write(b'\xAA')

        return frame

    def serve_once(self):
        if self.state == HiSTBBootROMState.POWER_DOWN:
            pass
        elif self.state == HiSTBBootROMState.BOOTROM_START:
            time.sleep(.5)
            self.dev.write(b"BootROM Start\r\nBootMedia: eMMC\r\n")
            # start a timer for 0.5 seconds
            def f(self):
                self.timeout = True
            self._timer = threading.Timer(.5, f, (self, ))
            self._timer.run()
            self.state += 1
        elif self.state == HiSTBBootROMState.WAIT_TYPE_FRAME:
            if self.timeout:
                # No type frame is found before timeout
                self.state = HiSTBBootROMState.ERROR
            else:
                try:
                    self._read_packet(b'\xFF', 13, False)
                except TimeoutError:
                    pass
                except RuntimeError:
                    pass
                else:
                    # Return the type frame
                    self.dev.write(bytes(self.chipid))
                    self.state += 1
        elif self.state == HiSTBBootROMState.WAIT_HEAD_AREA:
            ...

    def start_loop(self):
        self.state = HiSTBBootROMState.BOOTROM_START
        while not self.state in (HiSTBBootROMState.DONE, HiSTBBootROMState.ERROR):
            self.serve_once()

