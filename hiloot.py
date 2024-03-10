#!/usr/bin/env python3

import asyncio
import binascii
from enum import IntEnum
import logging
from struct import Struct
from typing import TYPE_CHECKING, ClassVar, Iterable, Literal, NamedTuple, \
    SupportsBytes, SupportsIndex, cast, overload
import serial
import serial.tools.list_ports
import serial.tools.miniterm
import serial_asyncio
import sys

from utils.serial import *
from utils.tqdm import tqdm
from bootimg import OTPID, BootParam, BootParamError, Memcpy

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer, SupportsWrite
    from utils.tqdm import _SupportsWriteAndFlush

    Bytesable = Iterable[SupportsIndex] | SupportsIndex | SupportsBytes | \
        ReadableBuffer


__all__ = [
    'TypeRequest', 'HeadRequest', 'ChipID', 'FrameType', 'Frame',
    'DeviceError', 'Device']


class RequestFrameMixin:
    __slots__ = ()

    STRUCT: ClassVar[Struct] = Struct('>B2I')

    def __bytes__(self):
        return self.STRUCT.pack(self.flags, self[0], self[1])  # type: ignore

    @classmethod
    def from_bytes(cls, data: bytes):
        _, arg1, arg2 = cls.STRUCT.unpack(data)
        return cls(arg1, arg2)


class _TypeRequest(NamedTuple):
    use_onboard_fastboot: bool
    "(notBareBurn)"
    to_ddr: bool
    "`True` if flash type is DDR (ddrOrFlash)"

    @property
    def flags(self):
        return 1


class TypeRequest(_TypeRequest, RequestFrameMixin):
    """The payload of request Type frame."""
    __slots__ = ()


class _HeadRequest(NamedTuple):
    size: int
    "data size"
    addr: int
    "load address"

    @property
    def flags(self):
        return 1


class HeadRequest(_HeadRequest, RequestFrameMixin):
    """The payload of Head frame."""
    __slots__ = ()


class _ChipID(NamedTuple):
    chipid: int
    sysid: int
    ca: bool
    tee: bool
    multiform: bool

    @property
    def flags(self):
        return self.multiform << 2 | self.tee << 1 | self.ca

    def __str__(self):
        f = list[str]()
        if self.ca:
            f.append('ca')
        if self.tee:
            f.append('tee')
        if self.multiform:
            f.append('multiform')
        flags = f', {" ".join(f)}' if f else ''
        return (
            f'Hi{self.sysid >> 16:X}v{self.sysid & 0xffff:X}, '
            f'chip {self.chipid:X}{flags} (0x{bytes(self).hex()})')


class ChipID(_ChipID, RequestFrameMixin):
    """The payload of reply Type frame."""
    __slots__ = ()

    @classmethod
    def from_bytes(cls, data: 'Bytesable'):
        r"""
        Parse bytes into ChipID.

        >>> ChipID.from_bytes(b'\x08\x00\x00\x00\x037\x98\x03\x00').chipid
        3
        """
        flags, chipid, sysid = cls.STRUCT.unpack(bytes(data))
        ca = bool(flags & 1)
        tee = bool(flags & 2)
        multiform = bool(flags & 4)
        return cls(chipid, sysid, ca, tee, multiform)


class FrameType(IntEnum):
    __slots__ = ()

    NONE = 0
    TYPE = 0xbd
    "get board info"
    HEAD = 0xfe
    "set up load address and data length"
    DATA = 0xda
    "send data"
    TAIL = 0xed
    "finish sending data"
    BOARD = 0xce
    "get board variant"


class _Frame(NamedTuple):
    type: FrameType
    seq: int
    """
    auto-incremented sequence number when sending files (:attr:`FrameType.HEAD`,
    :attr:`FrameType.DATA`, :attr:`FrameType.TAIL`), otherwise set to 0
    """
    payload: 'ReadableBuffer'


class Frame(_Frame):
    """HiSi variant of XMODEM."""
    __slots__ = ()

    STRUCT: ClassVar[Struct] = Struct('>3B')

    def __bytes__(self):
        return \
            self.STRUCT.pack(self.type, self.seq & 0xff, ~self.seq & 0xff) + \
            bytes(self.payload)

    def to_bytes(self, with_crc=False):
        buf = bytes(self)
        return buf if not with_crc else \
            buf + binascii.crc_hqx(buf, 0).to_bytes(2, 'big')

    @classmethod
    def is_valid(cls, buf: 'ReadableBuffer'):
        view = memoryview(buf)
        return int.from_bytes(view[-2:], 'big') == \
            binascii.crc_hqx(view[:-2], 0)

    @classmethod
    def from_bytes(cls, buf: 'ReadableBuffer', with_crc=False):
        view = memoryview(buf)

        if with_crc:
            if not cls.is_valid(view):
                raise ValueError('invalid checksum')
            view = view[:-2]

        type_: int
        seq: int
        type_, seq, _ = cls.STRUCT.unpack(view[:3])

        return cls(FrameType(type_), seq, view[3:])


class DeviceError(Exception):
    __slots__ = ()


class Device(SerialMux):
    """Send or receive data from HiSi device."""

    timeout: float | None
    "timeout for frame reading"
    logbuf: '_SupportsWriteAndFlush[str] | None'
    "logger for instruction messages"

    connected: bool
    chip: ChipID | None
    boardvar: int | None

    __slots__ = tuple(__annotations__)

    def __init__(
            self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
            timeout: float | None = 3.,
            serbuf: 'SupportsWrite[bytes] | bool' = False):
        super().__init__(
            reader, writer, logger=SerialLogger(sys.stderr)
            if serbuf is True else serbuf if serbuf else None)
        self.timeout = timeout
        self.logbuf = sys.stderr

        self.connected = False
        self.chip = None
        self.boardvar = None

    @overload
    async def send_frame(
        self, type: FrameType, seq: int, payload: 'ReadableBuffer',
        reply_type: Literal[False] | None = None,
        timeout: float | None = None) -> None: ...

    @overload
    async def send_frame(
        self, type: FrameType, seq: int, payload: 'ReadableBuffer',
        reply_type: FrameType | Literal[True],
        timeout: float | None = None) -> Frame: ...

    async def send_frame(
            self, type: FrameType, seq: int, payload: 'ReadableBuffer',
            reply_type: FrameType | bool | None = None,
            timeout: float | None = None):
        """Send frame and wait for frame reply of ``reply_type``."""
        if not self.connected:
            raise DeviceError('device not connected')

        if isinstance(reply_type, bool):
            reply_type = type if reply_type else None

        def validator(data: bytes):
            if data[-1] != 0xaa:
                return False
            if reply_type is None:
                return True

            if len(data) < 7:
                return False
            if data[0] != reply_type or data[1] != seq & 0xff:
                return False
            if not Frame.is_valid(memoryview(data)[:-1]):
                return False
            return True

        if timeout is None:
            timeout = self.timeout

        async with asyncio.timeout(timeout):
            reply = await self.communicate(
                Frame(type, seq, payload).to_bytes(True), validator)

        if reply_type is None:
            return
        return Frame.from_bytes(memoryview(reply)[:-3])

    async def send_file(
            self, addr: int, size: int, data: 'ReadableBuffer', name='data'):
        """Send ``data`` to device memory ``addr``."""
        if not size:
            return

        if self.logbuf:
            print(f'Send {name} to {addr:#x}, length {size:#x}...',
                  file=self.logbuf)

        await self.send_frame(FrameType.HEAD, 0, bytes(HeadRequest(size, addr)))

        view = memoryview(data)
        n = (size + 1023) // 1024
        for i in tqdm(range(n), unit='KiB', file=self.logbuf):
            src = 1024 * i
            chunk = view[src:src + 1024] if src + 1024 <= size else \
                view[src:size]  # + b'\x00' * (src + 1024 - size)
            await self.send_frame(FrameType.DATA, i + 1, chunk)

        await self.send_frame(FrameType.TAIL, n + 1, b'')

    def send_region(self, region: Memcpy, name='data'):
        """Send ``region`` to device memory."""
        return self.send_file(region.addr, region.size, region.data, name)

    async def connect(
            self, timeout: float | None = None, superfluous: int | None = None):
        """Wait for the device to be power on."""
        if self.connected:
            return

        try:
            async with asyncio.timeout(timeout):
                if await self.wait(b'Bootrom start\r\n', superfluous):
                    self.connected = True
        except asyncio.TimeoutError:
            raise DeviceError('cannot connect to device')

    async def get_chip(self):
        """Get the SoC ID."""
        if self.chip is None:
            reply = await self.send_frame(
                FrameType.TYPE, 0, bytes(TypeRequest(False, True)), True)
            self.chip = ChipID.from_bytes(reply.payload)
        return self.chip

    async def get_boardvar(self):
        """Get the board reg file index."""
        if self.boardvar is None:
            reply = await self.send_frame(
                FrameType.BOARD, 0, b'\1' + b'\0' * 8, True)
            self.boardvar = int.from_bytes(
                memoryview(reply.payload)[:4], 'little')
        return self.boardvar

    async def detect(
            self, timeout: float | None = None, superfluous: int | None = None):
        print(
            'Please power cycle your device.\nWait device (re)booting...',
            file=self.logbuf)
        await self.connect(timeout, superfluous)
        print('Device is powered on', file=self.logbuf)

        print(f'Board info: {await self.get_chip()}', file=self.logbuf)
        print(f'Board use reg #{await self.get_boardvar()}', file=self.logbuf)

    async def boot(self, params: BootParam, image: 'ReadableBuffer'):
        """Boot HiSi device via serial port."""
        if not self.connected or self.chip is None or self.boardvar is None:
            raise DeviceError('device not connected')

        if self.boardvar >= len(params.regs) or not params.regs[self.boardvar]:
            raise DeviceError(
                f'board reg #{self.boardvar} not found in bootimg')

        # data transfer procedure, bootrom will only expect one transfer session
        # for each step, so it is not possible to split them apart

        # during bootrom processing data, it cannot accept further serial input,
        # so sleep a while to avoid retransmission

        await self.send_region(params.head, 'head data')

        await self.send_region(params.aux, 'auxiliary code')
        # auxiliary code will be decrypted here
        await asyncio.sleep(.5)

        if params.aux_enc_flag == OTPID.NORMAL:
            await self.send_region(Memcpy.cut(
                params.boot.end, 0x2a00, image), 'extra area')
        elif params.aux_enc_flag == OTPID.SB and params.extra_size:
            await self.send_region(Memcpy.cut(
                params.boot.end + params.extra_size * self.boardvar,
                params.extra_size, image), 'extra area')

        await self.send_region(params.regs[self.boardvar], 'reg')
        # auxiliary code will be executed here
        await asyncio.sleep(.5)

        # there is a big gap between params.head.addr and params.boot.addr,
        # however, the entry point is params.head.addr, all data must be sent
        # within one session
        await self.send_region(Memcpy.cut(
            params.head.addr, params.boot.end - params.head.addr, image
        ), 'bootimg')

        if 2 <= self.chip.chipid <= 3 and self.chip.ca and \
                params.multi_param and params.asc:
            await self.send_region(params.asc[:0x400], 'ACPU start code (1)')
            await self.send_region(params.asc[0x400:], 'ACPU start code (2)')


async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Boot LibBootrom-supported HiStb devices via serial port.')
    parser.add_argument(
        '-p', '--port', metavar='PATH', dest='ser_path',
        help='serial port to use (default: auto detect)')
    parser.add_argument(
        '--rate', metavar='RATE', dest='bandurate', default=115200, type=int,
        help='serial bandurate (default: 115200)')
    parser.add_argument(
        '--timeout', metavar='TIME', default=3., type=float,
        help='serial communication timeout in second (default: 3)')
    parser.add_argument(
        '--no-terminal', action='store_true',
        help='do not start internal terminal after booted')
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='debug')
    parser.add_argument(
        'bootimg', metavar='fastboot.bin', type=argparse.FileType('rb'),
        help='fastboot.bin to use')

    args = parser.parse_args()

    logger = logging.getLogger(__name__)

    try:
        from utils.coloredlog import setColoredLogger

        setColoredLogger(logger, args.debug)
    except ImportError:
        pass

    if args.ser_path:
        ser_path = cast(str, args.ser_path)
    else:
        infos = [
            info for info in serial.tools.list_ports.comports()
            if info.subsystem == 'usb-serial']
        if len(infos) == 0:
            print(
                'Error: No serial ports detected, use "-p PATH" to specify the '
                'path manually', file=sys.stderr)
            return 253
        elif len(infos) > 1:
            print(
                'Error: Multiple serial ports found, use "-p PATH" to specify '
                'one to use:', file=sys.stderr)
            for info in infos:
                print(f'  {info.name}: {info.device_path}', file=sys.stderr)
            return 253
        ser_path = infos[0].device
        print('Auto-select USB serial port: %s' % ser_path, file=sys.stderr)

    try:
        reader, writer = await serial_asyncio.open_serial_connection(
            url=ser_path, baudrate=115200)
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        return 1

    ser = cast(serial.Serial, cast(
        serial_asyncio.SerialTransport, writer.transport).serial)
    logger.info('Use serial port %s @ %d', ser.name, args.bandurate)

    dev = Device(reader, writer, args.timeout, args.debug)
    dev.logbuf = sys.stderr

    image = args.bootimg.read()

    try:
        await dev.detect()
        assert dev.chip is not None
        params = BootParam.parse(dev.chip.chipid, image)
        await dev.boot(params, image)
    except (DeviceError, BootParamError) as e:
        print('\nError: %s' % e, file=sys.stderr)
        return 2
    except asyncio.TimeoutError:
        print('\nError: Timeout', file=sys.stderr)
        return 3
    except serial.SerialException as e:
        print('\nError: Serial port error, %s' % e, file=sys.stderr)
        return 254
    except KeyboardInterrupt:
        print('\nError: Keyboard interrupt', file=sys.stderr)
        return 255

    print('Bootstrap finished.', file=sys.stderr)

    if not args.no_terminal:
        print(
            '\n'
            '============================================\n'
            'Use Ctrl+] to exit, Ctrl+H Ctrl+T shows help\n'
            '++++++++++++++++++++++++++++++++++++++++++++\n', file=sys.stderr)

        term = serial.tools.miniterm.Miniterm(ser, eol='lf')
        term.set_tx_encoding('utf-8')
        term.set_rx_encoding('utf-8')
        term.start()
        term.join()
    return 0


if __name__ == '__main__':
    exit(asyncio.run(main()))
