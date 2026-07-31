#!/usr/bin/env python3
#
# Copyright 2022-2026 Morse Micro
#
# SPDX-License-Identifier: Apache-2.0
#

"""Compress the segment TLVs in an existing Morse TLV binary (mbin)."""

import argparse
import logging
import os
import struct
import zlib

FIELD_TYPE_MAGIC = 0x8000
FIELD_TYPE_FW_SEGMENT = 0x8001
FIELD_TYPE_FW_SEGMENT_DEFLATED = 0x8002
FIELD_TYPE_SW_SEGMENT = 0x8201
FIELD_TYPE_SW_SEGMENT_DEFLATED = 0x8202
FIELD_TYPE_EOF = 0x8F00

SW_MAGIC_NUMBER = 0x57534D4D   # MMSW in little endian
FW_MAGIC_NUMBER = 0x57464D4D   # MMFW in little endian
BCF_MAGIC_NUMBER = 0x43424D4D  # MMBC in little endian

DEFAULT_COMPRESSION_CHUNK_SIZE = 8 * 1024
COMPRESSION_LEVEL = 1
TLV_HEADER_FORMAT = "<HH"
TLV_HEADER_SIZE = struct.calcsize(TLV_HEADER_FORMAT)


class MbinFormatError(ValueError):
    pass


class MbinWriter:
    def __init__(self, outfile, compression_chunk_size):
        self.outfile = outfile
        self.compression_chunk_size = compression_chunk_size
        self.compressed_segment_count = 0
        self.preserved_compressed_segment_count = 0
        self.preserved_tlv_count = 0
        self.tlv_count = 0

    def add_tlv(self, tlv_type, data):
        if len(data) > 0xFFFF:
            raise MbinFormatError(
                f"TLV type 0x{tlv_type:04x} is too large: {len(data)} bytes"
            )
        self.outfile.write(struct.pack(TLV_HEADER_FORMAT, tlv_type, len(data)))
        self.outfile.write(data)
        self.tlv_count += 1
        logging.debug("Added TLV of length %d, type 0x%04x", len(data), tlv_type)

    def add_compressed_segment(self, output_type, dest_address, data):
        for offset in range(0, len(data), self.compression_chunk_size):
            chunk = data[offset:offset + self.compression_chunk_size]
            chunk_address = dest_address + offset
            compressed_chunk = zlib.compress(chunk, level=COMPRESSION_LEVEL)
            payload = struct.pack("<IH", chunk_address, len(chunk)) + compressed_chunk

            logging.debug(
                "Compressed chunk @ %08x from %d to %d bytes",
                chunk_address,
                len(chunk),
                len(compressed_chunk),
            )
            self.add_tlv(output_type, payload)
            self.compressed_segment_count += 1

    def log_summary(self):
        logging.info(
            "Wrote %d compressed segments, preserved %d compressed segments, "
            "%d other TLVs, %d TLVs total",
            self.compressed_segment_count,
            self.preserved_compressed_segment_count,
            self.preserved_tlv_count,
            self.tlv_count,
        )


def _iter_tlvs(infile):
    offset = 0

    while True:
        header = infile.read(TLV_HEADER_SIZE)
        if not header:
            return
        if len(header) != TLV_HEADER_SIZE:
            raise MbinFormatError(f"Truncated TLV header at offset 0x{offset:x}")

        tlv_type, tlv_length = struct.unpack(TLV_HEADER_FORMAT, header)
        data = infile.read(tlv_length)
        if len(data) != tlv_length:
            raise MbinFormatError(
                f"Truncated TLV type 0x{tlv_type:04x} at offset 0x{offset:x}: "
                f"expected {tlv_length} bytes, got {len(data)}"
            )

        yield offset, tlv_type, data
        offset += TLV_HEADER_SIZE + tlv_length


def _validate_magic(tlv_type, data):
    if tlv_type != FIELD_TYPE_MAGIC or len(data) != 4:
        raise MbinFormatError("Input does not begin with a valid MBIN magic TLV")

    magic_number = struct.unpack("<I", data)[0]
    if magic_number == FW_MAGIC_NUMBER:
        return "firmware"
    if magic_number == SW_MAGIC_NUMBER:
        return "software"
    if magic_number == BCF_MAGIC_NUMBER:
        return "BCF"
    raise MbinFormatError(f"Unknown MBIN magic number 0x{magic_number:08x}")


def _compress_mbin(input_path, output_path, compression_chunk_size):
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must be different")
    if compression_chunk_size <= 0 or compression_chunk_size > 0xFFFF:
        raise ValueError("Compression chunk size must be between 1 and 65535 bytes")

    saw_magic = False
    saw_eof = False
    input_type = None

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        outbin = MbinWriter(outfile, compression_chunk_size)

        for offset, tlv_type, data in _iter_tlvs(infile):
            if saw_eof:
                raise MbinFormatError(
                    f"TLV type 0x{tlv_type:04x} follows EOF at offset 0x{offset:x}"
                )

            if not saw_magic:
                input_type = _validate_magic(tlv_type, data)
                saw_magic = True

            if tlv_type == FIELD_TYPE_FW_SEGMENT:
                if len(data) < 4:
                    raise MbinFormatError(
                        f"Firmware segment at offset 0x{offset:x} has no address"
                    )
                dest_address = struct.unpack_from("<I", data)[0]
                outbin.add_compressed_segment(
                    FIELD_TYPE_FW_SEGMENT_DEFLATED, dest_address, data[4:]
                )
            elif tlv_type == FIELD_TYPE_SW_SEGMENT:
                if len(data) < 4:
                    raise MbinFormatError(
                        f"Software segment at offset 0x{offset:x} has no address"
                    )
                dest_address = struct.unpack_from("<I", data)[0]
                outbin.add_compressed_segment(
                    FIELD_TYPE_SW_SEGMENT_DEFLATED, dest_address, data[4:]
                )
            else:
                outbin.add_tlv(tlv_type, data)
                if tlv_type in (
                    FIELD_TYPE_FW_SEGMENT_DEFLATED,
                    FIELD_TYPE_SW_SEGMENT_DEFLATED,
                ):
                    outbin.preserved_compressed_segment_count += 1
                else:
                    outbin.preserved_tlv_count += 1

            if tlv_type == FIELD_TYPE_EOF:
                saw_eof = True

        if not saw_magic:
            raise MbinFormatError("Input file is empty")
        if not saw_eof:
            raise MbinFormatError("Input MBIN does not contain an EOF TLV")

        if input_type == "BCF":
            logging.warning("Input is a BCF MBIN and contains no firmware segments to compress")
        elif outbin.compressed_segment_count == 0:
            logging.warning("No uncompressed segment TLVs were found")

        outbin.log_summary()

    input_size = os.stat(input_path).st_size
    output_size = os.stat(output_path).st_size
    delta = input_size - output_size
    saving = delta / input_size * 100 if input_size else 0
    logging.info(
        "Reduced file size from %.1f KB to %.1f KB -- %.1f KB (%.1f%%) saving",
        input_size / 1024,
        output_size / 1024,
        delta / 1024,
        saving,
    )


def _app_setup_args(parser):
    parser.add_argument("-o", "--output", required=True,
                        help="Filename for compressed MBIN output")
    parser.add_argument("-C", "--compress-chunk-size", type=int,
                        default=DEFAULT_COMPRESSION_CHUNK_SIZE,
                        help="Size of chunks to split into before compressing")
    parser.add_argument("input", help="Filename for uncompressed MBIN input")


def _main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity of log messages (repeat for debug output)")
    parser.add_argument("-l", "--log-file",
                        help="Log to the given file as well as to the console")
    _app_setup_args(parser)
    args = parser.parse_args()

    log_handlers = [logging.StreamHandler()]
    if args.log_file:
        log_handlers.append(logging.FileHandler(args.log_file))

    log_format = "%(asctime)s %(levelname)s: %(message)s"
    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose == 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    logging.basicConfig(level=log_level, format=log_format, handlers=log_handlers)

    try:
        import coloredlogs
        coloredlogs.install(fmt=log_format, level=logging.root.level)
    except ImportError:
        logging.debug("coloredlogs not installed")

    try:
        _compress_mbin(args.input, args.output, args.compress_chunk_size)
    except (OSError, ValueError, MbinFormatError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    _main()
