#!/usr/bin/env python3
#
# Copyright 2021-2026 Morse Micro
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Library Mangler
==================

"""

import argparse
import fnmatch
import hashlib
import logging
import os
import re
import shutil
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# Maps the name section type that nm provides to the full name of the section
SECTIONS_TO_MANGLE = {
    "T": "text",
    "t": "text",
    "R": "rodata",
    "r": "rodata",
    "D": "data",
    "d": "data",
    "B": "bss",
    "b": "bss",
}


# Generate a mangled name for a symbol from symbol hash
def _hash_symbol_name(symbol_name):
    return f'mmint_{hashlib.sha256(symbol_name.encode("utf-8")).hexdigest()[0:8]}'


# Generate a basic mangled name for a symbol
def _mangle_symbol_name(symbol_name):
    return f"mmint_{symbol_name}"


# Split a list into chunks with a maximum length
def chunk_list(lst, maxlen):
    for i in range(0, len(lst), maxlen):
        yield lst[i:i + maxlen]


def _main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t", "--toolchain-base", default="",
                        help="Prefix to be applied to toolchain commands")
    parser.add_argument("-m", "--metadata-dir", required=True,
                        help="Directory to place metadata in")
    parser.add_argument("-p", "--protected-symbol", action="append",
                        help="Do not mangle any symbols matching the given fnmatch pattern")
    parser.add_argument("-o", "--output",
                        help="Output filename (if not given, input will be overwritten)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity")
    parser.add_argument("-u", "--use-hash", action="store_true",
                        help="Use hash of symbol name in mangled output")
    parser.add_argument("library")
    args = parser.parse_args()

    objcopy = f"{args.toolchain_base}objcopy"
    nm = f"{args.toolchain_base}nm"

    output_lib = args.library
    if args.output:
        shutil.copyfile(args.library, args.output)
        output_lib = args.output

    if args.verbose > 1:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose > 0:
        logging.basicConfig(level=logging.INFO)

    if args.use_hash:
        mangler_function = _hash_symbol_name
    else:
        mangler_function = _mangle_symbol_name

    logger = logging.getLogger("main")

    # First run objcopy in place to strip unnecessary symbols
    # Keep debug, it's needed by some build systems' analysis tools (zephyr rom/ram report)
    subprocess.run([objcopy, "--strip-unneeded", "--keep-section=.debug*", output_lib], check=True)

    # Get a list of symbols from the library
    p = subprocess.run([nm, output_lib], check=True, capture_output=True)

    SYMBOL_RE = re.compile(r"(?P<address>[0-9a-fA-f]{8}) (?P<type>\w) (?P<name>\w+)")
    symbol_names = {}
    for line in p.stdout.decode("utf-8").splitlines():
        match = SYMBOL_RE.match(line)
        if match:
            section_type = match.group("type")
            symbol_name = match.group("name")
            if section_type not in SECTIONS_TO_MANGLE:
                logger.info(f"Skipping {section_type} {symbol_name}")
                continue

            skip = False
            for protected_symbol in args.protected_symbol:
                if fnmatch.fnmatchcase(symbol_name, protected_symbol):
                    logger.info(f"Skipping protected symbol {symbol_name}")
                    skip = True
                    break
            if skip:
                continue

            symbol_names[symbol_name] = section_type

    # Mangle the symbol names
    symbol_name_remap = {}
    section_name_remap = {}

    for symbol_name, section_type in symbol_names.items():
        logger.debug(f"{symbol_name} -> {section_type}")
        mangled_symbol_name = mangler_function(symbol_name)
        symbol_name_remap[symbol_name] = mangled_symbol_name

        section_base = SECTIONS_TO_MANGLE[section_type]
        section_name = f".{section_base}.{symbol_name}"
        mangled_section_name = f".{section_base}.{mangled_symbol_name}"
        section_name_remap[section_name] = mangled_section_name

    # Generate redefine syms file (which is convenient for metadata too)
    if not os.path.exists(args.metadata_dir):
        os.makedirs(args.metadata_dir, exist_ok=True)
    libname = os.path.splitext(os.path.basename(output_lib))[0]
    redefine_syms_file = os.path.join(args.metadata_dir, f"symbol-redefines-{libname}.txt")
    with open(redefine_syms_file, "w") as f:
        for orig, obfs in sorted(symbol_name_remap.items(), key=lambda item: item[1]):
            f.write(f"{orig:60s} {obfs}\n")

    subprocess.run([objcopy, f"--redefine-syms={redefine_syms_file}", output_lib], check=True)

    # Mangle section names

    # We limit number of sections we rename at a time so we don't make a command line that is
    # too long.
    SECTION_RENAMES_PER_INVOCATION = 32
    for section_names in chunk_list(list(section_name_remap.keys()),
                                    SECTION_RENAMES_PER_INVOCATION):
        args = [objcopy]
        for section_name in section_names:
            args += ["--rename-section", f"{section_name}={section_name_remap[section_name]}"]
        args.append(output_lib)
        subprocess.run(args, check=True)


if __name__ == "__main__":
    _main()
