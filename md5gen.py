#!/usr/bin/env python3

# md5gen.py
#
# Cross platform tool to generate MD5 sum files
#

# Copyright 2024 Bioplatforms Australia

# License - BSD 3-Clause
# https://github.com/BioplatformsAustralia/md5gen/blob/master/LICENSE.txt

# This script should be cross platform and work on Linux, Windows and MacOS

# All imports should be from the base python
import sys
import platform
import os
import hashlib
import argparse
import re

if __name__ == "__main__":
    # Complain if we are not running Python 3.4 or later

    if not sys.version_info >= (3, 4):
        print("Your python version appears to be too old.")
        print("A minimum of 3.4 is required.")
        print()
        print("Please upgrade.")
        sys.exit(3)


def generate_md5(file_path):
    md5_object = hashlib.md5()
    block_size = 64 * 1024 * md5_object.block_size

    f = open(file_path, "rb")
    chunk = f.read(block_size)
    while chunk:
        md5_object.update(chunk)
        chunk = f.read(block_size)

    return md5_object.hexdigest()


def check_md5sum(file_path, checksum):
    # Returns true if file matches checksum
    filename = file_path.split(os.path.sep)[-1]

    md5_hash = generate_md5(file_path)

    if md5_hash == checksum:
        print(f"{filename}: OK")
    else:
        print(f"{filename}: INVALID")

    return md5_hash == checksum


# fs walk code inspired from
# https://johnpili.com/python-batch-file-md5-checksum-generator-and-checker/


def generate_md5_file(file_name="checksum.md5", directory="."):
    with open(file_name, "w") as checksum_file:
        for root, dirs, files in os.walk(
            directory
        ):  # start walking in current path or directory, you can parameterize this if you want
            for file in files:
                if file == file_name or file in [
                    "md5gen.py",
                ]:
                    # Don't create a checksum of the MD5 file
                    continue
                dir_path = "%s%s" % (root, os.path.sep)
                md5_digest = generate_md5(f"{dir_path}{file}")
                clean_dir_path = re.sub(r"^\.(\/|\\)", "", dir_path)
                checksum_file.write(f"{md5_digest}  {clean_dir_path}{file}\n")
                checksum_file.flush()


def check_md5_file(file_name="checksum.md5"):
    with open(file_name, "r") as checksum_file:
        s = checksum_file.readline()
        while s:
            v = re.split(r"\W\W", s, maxsplit=1)
            validation_result = check_md5sum(checksum=v[0], file_path=v[1].rstrip())
            s = checksum_file.readline()


def main():
    description = """
md5gen.py

Cross platform tool to generate and check MD5 files
        """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, description=description
    )
    parser.add_argument("-c", "--check", action="store_true", help="Check MD5 file")
    parser.add_argument(
        "-m",
        "--md5-file",
        action="store",
        help="Filename of MD5 file",
        default="checksum.md5",
    )
    parser.add_argument(
        "-d", "--directory", action="store", help="Directory to scan", default="."
    )
    parser.add_argument("extra", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    parsed = parser.parse_args()

    if parsed.check:
        if parsed.extra:
            check_md5_file(file_name=parsed.extra[0])
        else:
            check_md5_file(file_name=parsed.md5_file)
    else:
        generate_md5_file(file_name=parsed.md5_file, directory=parsed.directory)
        print(f"{parsed.md5_file} written for directory {parsed.directory}")


if __name__ == "__main__":
    # execute only if run as a script
    main()
