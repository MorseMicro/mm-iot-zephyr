#!/usr/bin/env python3
#
# Copyright 2022-2023 Morse Micro
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tool to convert a Morse firmware and BCF files from elf binary format to Morse TLV binary
format (mbin).
"""

import argparse
import logging
import os
import re
import struct
import zlib

from elftools.elf.elffile import ELFFile

FIELD_TYPE_FW_TLV_BCF_ADDR = 0x0001
FIELD_TYPE_MAGIC = 0x8000
# This is Morse chip firmware
FIELD_TYPE_FW_SEGMENT = 0x8001
FIELD_TYPE_FW_SEGMENT_DEFLATED = 0x8002
FIELD_TYPE_BCF_BOARD_CONFIG = 0x8100
FIELD_TYPE_BCF_REGDOM = 0x8101
FIELD_TYPE_BCF_BOARD_DESC = 0x8102
FIELD_TYPE_BCF_BUILD_VER = 0x8103
# To avoid confusion host firmware is refered to as 'software'
FIELD_TYPE_SW_SEGMENT = 0x8201
FIELD_TYPE_SW_SEGMENT_DEFLATED = 0x8202
FIELD_TYPE_EOF = 0x8f00

SW_MAGIC_NUMBER = 0x57534d4d    # MMSW in little endian
FW_MAGIC_NUMBER = 0x57464d4d    # MMFW in little endian
BCF_MAGIC_NUMBER = 0x43424d4d   # MMBC in little endian

SKIP_ADDRESSES = [0x00400000, 0x00C00000, 0x08000000]

DEFAULT_COMPRESSION_CHUNK_SIZE = 8 * 1024

MAX_SEGMENT_DATA_SIZE = 0x8000

REGDOM_RE = re.compile(r".regdom_(?P<domain>[A-Z]{2})")


class MbinFile:
    def __init__(self, outfile, is_compression_enabled, compression_chunk_size):
        self.outfile = outfile
        self.compressed_segment_count = 0
        self.segment_count = 0
        self.tlv_count = 0
        self.is_compression_enabled = is_compression_enabled
        self.compression_chunk_size = compression_chunk_size

    def add_tlv(self, type, data):
        self.outfile.write(struct.pack("<HH", type, len(data)))
        self.outfile.write(data)
        self.tlv_count += 1
        logging.debug("Added TLV of length %d, type 0x%04x", len(data), type)

    def add_tlv_block(self, tlv_block, filter):
        offset = 0
        while offset < len(tlv_block):
            tlv_type, tlv_len = struct.unpack_from("<HH", tlv_block, offset)
            offset += struct.calcsize("<HH")
            if filter is None or tlv_type in filter:
                self.add_tlv(tlv_type, tlv_block[offset:offset + tlv_len])
            else:
                logging.debug("Filtering out TLV type %04x len %d", tlv_type, tlv_len)
            offset += tlv_len

    def add_headers(self, magic_number):
        self.add_tlv(FIELD_TYPE_MAGIC, struct.pack("<I", magic_number))

    def add_fw_segment(self, dest_address, data):
        if self.is_compression_enabled:
            for offset in range(0, len(data), self.compression_chunk_size):
                chunk = data[offset:offset + self.compression_chunk_size]
                chunk_addr = dest_address + offset
                compressed_chunk = zlib.compress(chunk, level=1)
                logging.debug("Compressed chunk @ %08x from %d to %d",
                              chunk_addr, len(chunk), len(compressed_chunk))
                self.add_tlv(FIELD_TYPE_FW_SEGMENT_DEFLATED, struct.pack("<IH",
                             chunk_addr, len(chunk)) + compressed_chunk)
                self.compressed_segment_count += 1
        else:
            while data:
                chunk_len = min(len(data), MAX_SEGMENT_DATA_SIZE)
                self.add_tlv(FIELD_TYPE_FW_SEGMENT,
                             struct.pack("<I", dest_address) + data[:chunk_len])
                self.segment_count += 1
                logging.debug("Added segment chunk of length %d (0x%04x) at %08x",
                              chunk_len, chunk_len, dest_address)
                data = data[chunk_len:]
                dest_address += chunk_len

    def add_sw_segment(self, dest_address, data):
        if self.is_compression_enabled:
            for offset in range(0, len(data), self.compression_chunk_size):
                chunk = data[offset:offset + self.compression_chunk_size]
                chunk_addr = dest_address + offset
                compressed_chunk = zlib.compress(chunk, level=1)
                logging.debug("Compressed chunk @ %08x from %d to %d",
                              chunk_addr, len(chunk), len(compressed_chunk))
                self.add_tlv(FIELD_TYPE_SW_SEGMENT_DEFLATED, struct.pack("<IH",
                             chunk_addr, len(chunk)) + compressed_chunk)
                self.compressed_segment_count += 1
        else:
            while data:
                chunk_len = min(len(data), MAX_SEGMENT_DATA_SIZE)
                self.add_tlv(FIELD_TYPE_SW_SEGMENT,
                             struct.pack("<I", dest_address) + data[:chunk_len])
                self.segment_count += 1
                logging.debug("Added segment chunk of length %d (0x%04x) at %08x",
                              chunk_len, chunk_len, dest_address)
                data = data[chunk_len:]
                dest_address += chunk_len

    def log_summary(self):
        logging.info("Wrote %d uncompressed segments, %d compressed segments, %d TLVs",
                     self.segment_count, self.compressed_segment_count, self.tlv_count)


def _pad_data(data):
    # Pad data out to a multiple of 4 bytes
    while len(data) % 4 != 0:
        data += b"\0"
    return data


def _app_setup_args(parser):
    parser.add_argument("-o", "--output", required=True,
                        help="Filename for compressed firmware output")
    parser.add_argument("-s", "--sw",
                        action="store_true",
                        help="Specifies file type as software image")
    parser.add_argument("input", help="Filename for elf file input")
    parser.add_argument("--compress", "-c", action="store_true",
                        help="If set then the data will be compressed. "
                             "WARNING: use this option at your own risk. It is not officially "
                             "supported and may result in increased boot time and may not be "
                             "robust. This option may be removed in future.")
    parser.add_argument("--compress-chunk-size", "-C", type=int,
                        default=DEFAULT_COMPRESSION_CHUNK_SIZE,
                        help="Size of chunks to split into before compressing.")
    parser.add_argument("--regdom-filter", "-F",
                        help="Optional comma separated list of regdoms to include. "
                             "If not specified, all regdoms will be included. "
                             "Applies to BCF conversion only.")
    parser.add_argument("--fw-info-filter", "-t",
                        help="Optional comma separated list of TLV IDs to include from the "
                             ".fw_info section of the firmware. "
                             "If not specified, all will be included. "
                             "Applies to firmware conversion only.")


def _app_main(args):
    if args.regdom_filter:
        regdom_filter = args.regdom_filter.upper().split(",")
    else:
        regdom_filter = None

    with open(args.output, "wb") as outfile:
        outbin = MbinFile(outfile, args.compress, args.compress_chunk_size)

        with open(args.input, "rb") as f:
            elffile = ELFFile(f)

            # Check if this is a BCF file or a firmware file. We take a simplistic approach and
            # assume that if it contains a .board_config section then it is a BCF file.
            if args.sw:
                file_type = "sw"
            else:
                file_type = "fw"
                for section in elffile.iter_sections():
                    if section.name == ".board_config":
                        file_type = "bcf"
                        break

            # Generate the appropriate header based on the type of file we detected above.
            if file_type == "fw":
                magic_number = FW_MAGIC_NUMBER
            elif file_type == "sw":
                magic_number = SW_MAGIC_NUMBER
            else:
                magic_number = BCF_MAGIC_NUMBER
            outbin.add_headers(magic_number)

            # Find and parse specific named sections section
            for section in elffile.iter_sections():
                if section.name == ".fw_info":
                    if args.fw_info_filter:
                        tlv_filter = [int(x) for x in args.fw_info_filter.split(",")]
                    else:
                        tlv_filter = None
                    outbin.add_tlv_block(section.data(), tlv_filter)
                elif section.name == ".board_config":
                    logging.debug("Adding .board_config TLV")
                    outbin.add_tlv(FIELD_TYPE_BCF_BOARD_CONFIG, _pad_data(section.data()))
                elif section.name == ".board_desc":
                    logging.debug("Adding .board_desc TLV")
                    outbin.add_tlv(FIELD_TYPE_BCF_BOARD_DESC, _pad_data(section.data()))
                elif section.name == ".build_ver":
                    logging.debug("Adding .build_ver TLV")
                    outbin.add_tlv(FIELD_TYPE_BCF_BUILD_VER, _pad_data(section.data()))
                else:
                    match = REGDOM_RE.match(section.name)
                    if match:
                        domain = match.group("domain")
                        if regdom_filter and domain not in regdom_filter:
                            logging.debug("Filtering out .regdom %s", domain)
                            continue
                        logging.debug("Adding .regdom TLV for %s", domain)
                        outbin.add_tlv(FIELD_TYPE_BCF_REGDOM,
                                       domain.encode("utf-8") + b"\0\0" + _pad_data(section.data()))

            # Now find and add all loadable segments
            if file_type != "bcf":
                for segment in elffile.iter_segments():
                    if segment["p_type"] != "PT_LOAD":
                        logging.info("Skipping segment because type is not PT_LOAD")
                        continue
                    addr = segment["p_paddr"]
                    if addr in SKIP_ADDRESSES:
                        logging.info("Skipping segment because address is 0x%08x", addr)
                        continue

                    if file_type == "sw":
                        outbin.add_sw_segment(addr, _pad_data(segment.data()))
                    else:
                        outbin.add_fw_segment(addr, _pad_data(segment.data()))

        outbin.add_tlv(FIELD_TYPE_EOF, b"")
        outbin.log_summary()

    in_file_size = os.stat(args.input).st_size / 1024
    out_file_size = os.stat(args.output).st_size / 1024

    delta = in_file_size - out_file_size
    logging.info("Reduced file size from %d KB to %d KB -- %d KB (%d %%) saving",
                 in_file_size, out_file_size, delta, delta / in_file_size * 100)


#
# ---------------------------------------------------------------------------------------------
#


def _main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description=__doc__)
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity of log messages (repeat for increased verbosity)")
    parser.add_argument("-l", "--log-file",
                        help="Log to the given file as well as to the console")

    _app_setup_args(parser)

    args = parser.parse_args()

    # Configure logging
    log_handlers = [logging.StreamHandler()]
    if args.log_file:
        log_handlers.append(logging.FileHandler(args.log_file))

    LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT, handlers=log_handlers)
    elif args.verbose == 1:
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=log_handlers)
    else:
        logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT, handlers=log_handlers)

    # If coloredlogs package is installed, then use it to get pretty coloured log messages.
    # To install:
    #    pip3 install coloredlogs
    try:
        import coloredlogs
        coloredlogs.install(fmt=LOG_FORMAT, level=logging.root.level)
    except ImportError:
        logging.debug("coloredlogs not installed")

    _app_main(args)


if __name__ == "__main__":
    _main()
