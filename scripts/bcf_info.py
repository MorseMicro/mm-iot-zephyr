#!/usr/bin/env python3
#
# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0
#
"""
Parse a Morse Micro BCF (mbin) file to determine which regulatory domains
it supports, and optionally verify the chip type it was built for.
"""

import argparse
import struct
import sys

FIELD_TYPE_MAGIC = 0x8000
FIELD_TYPE_BCF_REGDOM = 0x8101
FIELD_TYPE_BCF_CHIPS = 0x8104
FIELD_TYPE_EOF = 0x8f00

BCF_MAGIC_NUMBER = 0x43424d4d  # "MMBC" in little endian

TLV_HEADER = struct.Struct("<HH")

# Chip family identifier stored in the FIELD_TYPE_BCF_CHIPS TLV, keyed by the
# chip name used in the devicetree "compatible" property.
CHIP_TLV_IDS = {
    "mm6108": b"mm610x",
    "mm8108": b"mm810x",
}


class BcfParseError(Exception):
    pass


def parse_bcf(data):
    """Return (regdoms, chip) parsed from a BCF's TLV stream.

    regdoms is a list of 2-letter country codes, in the order they appear.
    chip is the raw (NUL-stripped) payload of the chip TLV, or None if absent.
    """
    if len(data) < TLV_HEADER.size:
        raise BcfParseError("file is too small to contain a TLV header")

    magic_type, magic_len = TLV_HEADER.unpack_from(data, 0)
    offset = TLV_HEADER.size
    magic = int.from_bytes(data[offset:offset + magic_len], "little")
    offset += magic_len
    if magic_type != FIELD_TYPE_MAGIC or magic != BCF_MAGIC_NUMBER:
        raise BcfParseError("missing or invalid BCF magic number")

    regdoms = []
    chip = None
    while offset + TLV_HEADER.size <= len(data):
        tlv_type, tlv_len = TLV_HEADER.unpack_from(data, offset)
        offset += TLV_HEADER.size
        payload = data[offset:offset + tlv_len]
        offset += tlv_len

        if tlv_type == FIELD_TYPE_BCF_REGDOM:
            regdoms.append(payload[:2].decode("ascii"))
        elif tlv_type == FIELD_TYPE_BCF_CHIPS:
            chip = payload.rstrip(b"\0")
        elif tlv_type == FIELD_TYPE_EOF:
            break

    # Preserve order, drop duplicates (a BCF may carry more than one regdom
    # section per country for different sub-bands).
    return list(dict.fromkeys(regdoms)), chip


def main():
    parser = argparse.ArgumentParser(
        description="Print the regulatory regions supported by a Morse Micro BCF "
                    "as a semicolon-separated list, and verify its chip type.")
    parser.add_argument("bcf", help="Path to the BCF (.mbin) file")
    parser.add_argument("--chip", choices=sorted(CHIP_TLV_IDS),
                        help="Chip type determined by the devicetree compatible. If given, this is "
                            "cross-checked against the BCF's own chip type TLV.")
    args = parser.parse_args()

    try:
        with open(args.bcf, "rb") as f:
            data = f.read()
        regdoms, chip = parse_bcf(data)
    except (OSError, BcfParseError) as e:
        print(f"error: failed to parse BCF '{args.bcf}': {e}", file=sys.stderr)
        return 1

    if not regdoms:
        print(f"error: BCF '{args.bcf}' contains no regulatory domain TLVs", file=sys.stderr)
        return 1

    if args.chip:
        expected = CHIP_TLV_IDS[args.chip]
        if chip is None:
            print(f"error: BCF '{args.bcf}' has no chip type TLV, "
                  f"expected '{expected.decode()}' for chip '{args.chip}'", file=sys.stderr)
            return 1
        if chip != expected:
            print(f"error: BCF '{args.bcf}' is built for chip type "
                  f"'{chip.decode(errors='replace')}', but the devicetree specifies "
                  f"'{args.chip}' (expected '{expected.decode()}')", file=sys.stderr)
            return 1

    print(";".join(regdoms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
