#!/usr/bin/env python3

import functools
import argparse
import ctypes
import io
import plistlib
import struct
import sys
import time


def load_cdll():
    if sys.platform == 'linux':
        for n in (6, 5, 4, 3, 2, 1, 0):
            for sfx in ('-1.0', ''):
                try:
                    return ctypes.CDLL('libimobiledevice{}.so.{}'.format(sfx, n))
                except OSError:
                    pass
        raise OSError('libimobiledevice not found!')
    elif sys.platform == 'win32':
        import hashlib
        import tempfile
        import shutil
        import os
        from zipfile import ZipFile
        from urllib.request import urlopen
        if sys.maxsize >> 32:
            imd_url = 'https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/v1.3.17/libimobiledevice.1.2.1-r1122-win-x64.zip'
        else:
            imd_url = 'https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/v1.3.17/libimobiledevice.1.2.1-r1122-win-x86.zip'
        imd_comp = 'imobiledevice-' + hashlib.sha1(imd_url.encode()).hexdigest()
        imd_dir = os.path.join(tempfile.gettempdir(), imd_comp)
        dll_path = os.path.join(imd_dir, 'imobiledevice.dll')
        if not os.path.exists(dll_path):
            print('Downloading libimobiledevice ...', file=sys.stderr)
            dnld_dir = imd_dir + '-download'
            dnld_zip = dnld_dir + '.zip'
            with urlopen(imd_url) as in_fd, open(dnld_zip, 'wb') as out_fd:
                shutil.copyfileobj(in_fd, out_fd)
            print('Extracting libimobiledevice ...', file=sys.stderr)
            shutil.rmtree(dnld_dir, ignore_errors=True)
            shutil.rmtree(imd_dir, ignore_errors=True)
            with ZipFile(dnld_zip) as zf:
                zf.extractall(dnld_dir)
            os.rename(dnld_dir, imd_dir)
        ctypes.windll.kernel32.SetDllDirectoryW(ctypes.c_wchar_p(imd_dir))
        return ctypes.CDLL(dll_path)
    else:
        raise OSError('unsupported platform: {}'.format(sys.platform))

cdll = load_cdll()


class LIDError(Exception):
    @classmethod
    def check(cls, err):
        if err != 0:
            raise cls(err)

class IDeviceError(LIDError):
    def __str__(self):
        [code] = self.args
        err = 'Error in libimobiledevice: ' + {
            0: 'Success',
            -1: 'Invalid Argument',
            -2: 'Unknown Error',
            -3: 'No Device',
            -4: 'Not Enough Data',
            -5: 'Bad Header',
            -6: 'SSL Error',
            -7: 'Timeout',
        }.get(code) or 'Unknown Error Code {}'.format(code)
        if code == -3:
            if sys.platform == 'linux':
                err += ' (device not connected? usbmuxd not running?)'
            elif sys.platform == 'win32':
                err += ' (device not connected? iTunes not installed?)'
        return err


class LockdownError(LIDError):
    pass

class LIDContainer(object):
    handle = None
    destructor = None
    error_class = None
    def __init__(self, *args, **kwargs):
        self.handle = self._init_handle(*args, **kwargs)
    def __del__(self):
        if self.handle:
            self.error_class.check(self.destructor(self.handle))
    def _init_handle(self, *args, **kwargs):
        raise NotImplementedError

class IDevice(LIDContainer):
    destructor = cdll.idevice_free
    error_class = IDeviceError
    def _init_handle(self, udid=None):
        udid = udid.encode() if udid is not None else ctypes.c_void_p(0)
        handle = ctypes.c_void_p(0)
        IDeviceError.check(cdll.idevice_new(ctypes.byref(handle), udid))
        return handle

class IDeviceConnection(LIDContainer):
    idevice_connection_receive_timeout = cdll.idevice_connection_receive_timeout
    idevice_connection_receive_timeout.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p,
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint]
    destructor = cdll.idevice_disconnect
    error_class = IDeviceError
    def _init_handle(self, idevice, port):
        self.idevice = idevice
        handle = ctypes.c_void_p(0)
        IDeviceError.check(cdll.idevice_connect(
            idevice.handle, ctypes.c_uint16(port), ctypes.byref(handle)))
        return handle
    def enable_ssl(self):
        IDeviceError.check(cdll.idevice_connection_enable_ssl(self.handle))
    def disable_ssl(self):
        IDeviceError.check(cdll.idevice_connection_disable_ssl(self.handle))
    def recv(self, num_bytes):
        out = bytes(num_bytes)
        out_bytes = ctypes.c_uint32(0)
        IDeviceError.check(self.idevice_connection_receive_timeout(
            self.handle, out, num_bytes, ctypes.byref(out_bytes), ctypes.c_uint(600 * 1000))) # 10 minutes
        return out[:out_bytes.value]

class LockdownService(LIDContainer):
    destructor = cdll.lockdownd_client_free
    error_class = LockdownError
    def _init_handle(self, idevice):
        self.idevice = idevice
        handle = ctypes.c_void_p(0)
        LockdownError.check(cdll.lockdownd_client_new_with_handshake(
            idevice.handle, ctypes.byref(handle), __file__))
        return handle
    def start_service(self, name):
        service_desc_p = ctypes.POINTER(self.ServiceDescriptor)()
        LockdownError.check(cdll.lockdownd_start_service(
            self.handle, name.encode(), ctypes.byref(service_desc_p)))
        svc_port = service_desc_p.contents.port
        svc_ssl = bool(service_desc_p.contents.ssl)
        LockdownError.check(cdll.lockdownd_service_descriptor_free(service_desc_p))
        return svc_port, svc_ssl
    class ServiceDescriptor(ctypes.Structure):
        _fields_ = [
            ('port', ctypes.c_uint16),
            ('ssl', ctypes.c_uint8),
        ]


# based on https://opensource.apple.com/source/xnu/xnu-2050.48.11/bsd/net/iptap.h.auto.html
HEADER_STRUCT = struct.Struct('>IBIBHBIII 16s I 17s I I 17s II')
HEADER_SIZE = HEADER_STRUCT.size
UB32 = struct.Struct('>I')
SL32 = struct.Struct('<i')
UM32 = struct.Struct('=I')
UM16 = struct.Struct('=H')


class Packet(object):
    __slots__ = tuple('in_out proto_family iface_name '
                      'proc eproc svc_class epoch_usecs is_eth pkt_payload'.split())

    def __init__(self, **kwargs):
        try:
            for k, v in kwargs.items():
                setattr(self, k, v)
        except AttributeError:
            raise TypeError


class PacketExtractor(object):
    IN_OUT_MAP = {0x01: 'O', 0x10: 'I'}

    def __init__(self, udid=None):
        idevice = IDevice(udid=udid)
        port, ssl = LockdownService(idevice).start_service('com.apple.pcapd')
        self.conn = IDeviceConnection(idevice, port)    # keep reference to keep fd open
        ssl and self.conn.enable_ssl()

    def __iter__(self):
        conn = self.conn
        ctp = self._chunk_to_packet
        def read_fully(n):
            b = bytearray()
            l = 0
            while l < n:
                b += conn.recv(n - l)
                l = len(b)
            return b
        while True:
            try:
                [chunk_len] = UB32.unpack(read_fully(4))
            except (ValueError, struct.error):
                raise EOFError
            chunk = read_fully(chunk_len)
            if len(chunk) != chunk_len:
                raise EOFError
            chunk = plistlib.loads(chunk)
            if type(chunk) is not bytes:
                raise TypeError('got non-data chunk')
            yield ctp(chunk)

    def _chunk_to_packet(self, chunk):
        if len(chunk) < HEADER_SIZE:
            raise ValueError('chunk too small')
        chunk = memoryview(chunk)
        (hdr_len, hdr_version, payload_len, if_type, if_unit, in_out,
         proto_family, pre_len, post_len, iface_name,
         pid, comm, svc_class, epid, ecomm,
         epoch_secs, epoch_usecs) = HEADER_STRUCT.unpack(chunk[:HEADER_SIZE])
        if hdr_len < HEADER_SIZE:
            raise ValueError('header too small')
        payload = chunk[hdr_len:]
        if not (hdr_version == 2 and len(payload) == payload_len):
            raise ValueError('unsupported version')

        [pid] = SL32.unpack(UB32.pack(pid))
        [epid] = SL32.unpack(UB32.pack(epid))
        [svc_class] = SL32.unpack(UB32.pack(svc_class))
        iface_name = iface_name.rstrip(b'\0').decode('ascii') + str(if_unit)
        comm = comm.rstrip(b'\0').decode('utf-8')
        ecomm = ecomm.rstrip(b'\0').decode('utf-8')

        if if_type == 0xFF:
            is_eth = False  # cellular
            payload = payload[4:] # these lead with 4-byte protocol family that should be stripped
        elif if_type == 0x01:
            is_eth = False  # ipsec
            payload = payload[4:]
        elif if_type == 0x06:
            is_eth = True   # wifi
        else:
            raise ValueError('unknown link type {}'.format(hex(if_type)))

        return Packet(in_out=self.IN_OUT_MAP.get(in_out, 'U'),
                      proto_family=proto_family,
                      iface_name=iface_name,
                      proc=(comm, pid),
                      eproc=(ecomm, epid),
                      svc_class=svc_class,
                      epoch_usecs=epoch_secs * 1000000 + epoch_usecs,
                      is_eth=is_eth,
                      pkt_payload=payload)


class PacketDumper(object):
    def __init__(self, pkt_iter, out_file):
        self.pkt_iter = pkt_iter
        self.out_file = out_file
    def run(self, packet_cb=None):
        raise NotImplementedError


class NGPacketDumper(PacketDumper):
    SECTION_BLOCK_STRUCT = struct.Struct('=IHHq')
    INTERFACE_BLOCK_STRUCT = struct.Struct('=HHI')
    ENHANCED_PACKET_STRUCT = struct.Struct('=IIIII')
    OPTION_HEADER_STRUCT = struct.Struct('=HH')
    IN_OUT_TO_EPBFLAGS = {'I': 0b01, 'O': 0b10, 'U': 0b00}

    def run(self, packet_cb=None):
        # write section block
        self._write_block(0x0A0D0D0A,
                          self.SECTION_BLOCK_STRUCT.pack(0x1A2B3C4D, 1, 0, -1))
        # process packets
        if_name_to_idx = {}
        next_if_idx = 0
        for pkt in self.pkt_iter:
            packet_cb is not None and packet_cb(pkt)
            if_name = pkt.iface_name
            if_idx = if_name_to_idx.setdefault(if_name, next_if_idx)
            if if_idx == next_if_idx:
                # write interface block
                self._write_block(1, self.INTERFACE_BLOCK_STRUCT.pack(
                    1 if pkt.is_eth else 101, 0, 0xFFFFFFFF),
                    {2: if_name.encode()}) # if_name
                next_if_idx += 1
            # write packet block
            payload_len = len(pkt.pkt_payload)
            pcap_hdr = self.ENHANCED_PACKET_STRUCT.pack(
                if_idx,
                pkt.epoch_usecs >> 32, pkt.epoch_usecs & 0xFFFFFFFF,
                payload_len, payload_len)
            self._write_block(6, pcap_hdr + pkt.pkt_payload,
                              {2: UM32.pack(self.IN_OUT_TO_EPBFLAGS[pkt.in_out])})

    def _write_block(self, blk_type, blk_data, blk_options={}):
        blks = [UM32.pack(blk_type), b'']
        blks += (blk_data, b'\0' * (-len(blk_data) % 4))
        for code, val in blk_options.items():
            blks += (self.OPTION_HEADER_STRUCT.pack(code, len(val)),
                     val, b'\0' * (-len(val) % 4))
        blks += (b'\0\0\0\0',) # end of options
        total_len = sum(len(x) for x in blks) + 8
        total_len_b = UM32.pack(total_len)
        blks[1] = total_len_b
        blks += (total_len_b,)
        self.out_file.write(b''.join(blks))


class PCAPPacketDumper(PacketDumper):
    HEADER_STRUCT = struct.Struct('=IHHiIII')
    PACKET_STRUCT = struct.Struct('=IIII')

    def run(self, packet_cb=None):
        self.out_file.write(self.HEADER_STRUCT.pack(0xa1b2c3d4, 2, 4, 0, 0, 0xFFFFFFFF, 1))
        for pkt in self.pkt_iter:
            packet_cb is not None and packet_cb(pkt)
            payload = pkt.pkt_payload
            if not pkt.is_eth:
                # add a fake ethernet header
                if pkt.proto_family == 2:
                    ether_type_b = b'\x08\x00' # IPv4
                elif pkt.proto_family == 30:
                    ether_type_b = b'\x86\xDD' # IPv6
                else:
                    raise NotImplementedError('unsupported proto family {}'.format(pkt.proto_family))
                payload = b''.join((bytes(12), ether_type_b, payload))
            header = self.PACKET_STRUCT.pack(pkt.epoch_usecs // 1000000,
                                             pkt.epoch_usecs % 1000000,
                                             len(payload), len(payload))
            self.out_file.writelines((header, payload))


stderr_print = functools.partial(print, file=sys.stderr)

def main():
    # turn off buffered output
    if isinstance(sys.stdout.buffer, io.BufferedWriter):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer.detach())
    # parse arguments
    class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault('max_help_position', 36)
            super().__init__(*args, **kwargs)
    parser = argparse.ArgumentParser(description='Captures packets from iOS devices.',
                                     formatter_class=HelpFormatter)
    parser.add_argument('--format',
                        choices=('pcap', 'pcapng'), default='pcapng',
                        help='capture format')
    parser.add_argument('--udid', help='device UDID (if more than 1 device)')
    parser.add_argument('outfile', help='output file (- for stdout)')
    args = parser.parse_args()
    # open output file
    if args.outfile == '-':
        out_file = sys.stdout.buffer
        while isinstance(out_file, io.BufferedWriter):
            out_file = out_file.detach()
    else:
        out_file = open(args.outfile, 'wb', 0)
    # determine format to use
    dumper_class = {
        'pcap':   PCAPPacketDumper,
        'pcapng': NGPacketDumper,
    }[args.format]
    # start capture
    stderr_print('capturing to {} ...'.format('<stdout>' if args.outfile == '-' else args.outfile))
    num_packets = 0
    def packet_callback(pkt):
        nonlocal num_packets
        num_packets += 1
        stderr_print('\r{} packets captured.'.format(num_packets), end='', flush=True)
    try:
        packet_extractor = PacketExtractor(udid=args.udid)
        packet_dumper = dumper_class(packet_extractor, out_file)
        packet_dumper.run(packet_callback)
    except KeyboardInterrupt:
        stderr_print()
        stderr_print('closing capture ...')
        out_file.close()
    except:
        stderr_print()
        raise

if __name__ == '__main__':
    main()
