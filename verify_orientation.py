#!/usr/bin/env python

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import requests
import getpass
from math import sin, cos, sqrt, atan2, radians

TOKEN = None
HOST = None

# exiftool usage from here: https://stackoverflow.com/questions/10075115/call-exiftool-from-a-python-script
# modified to use bytes and 'read1' from the fd (not the actual fileno) per an IRC conversation and the
# original method having utf-8 decode issues.
class ExifTool(object):

    sentinel = b"{ready}\n"

    def __init__(self, executable="/usr/bin/exiftool"):
        self.executable = executable

    def __enter__(self):
        self.process = subprocess.Popen(
            [self.executable, "-stay_open", "True", "-@", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.process.stdin.write(bytes("-stay_open\nFalse\n", 'utf-8'))
        self.process.stdin.flush()

    def execute(self, *args):
        args = args + ("-execute\n",)
        self.process.stdin.write(bytes(str.join("\n", args), 'utf-8'))
        self.process.stdin.flush()
        output = b""
        fd = self.process.stdout
        while not output.endswith(self.sentinel):
            output += fd.read1(1024)
        output = output.decode('utf-8')
        return output[: -len(self.sentinel)]

    def get_metadata(self, *filenames):
        return json.loads(self.execute("-j", "-n", *filenames))

def process_file(fname, args):
    image_path, extension = os.path.splitext(fname)

    # only process XMP sidecars
    if extension.lower() != '.xmp':
        return

    if not os.path.isfile(image_path):
        return

    filename = os.path.basename(fname)

    # safeguard, don't touch files that are too new
    mtime = os.path.getmtime(fname)
    if datetime.now().timestamp() - mtime < 60:
       print("  File is too new. Skipping.")
       return

    # print(f'Processing {fname}')

    xmp_exif = e.get_metadata(fname)[0]
    file_exif = e.get_metadata(image_path)[0]

    if 'Orientation' not in xmp_exif and 'Orientation' not in file_exif:
        return

    if 'Orientation' not in xmp_exif or 'Orientation' not in file_exif:
        print(f"{image_path}")
        return

    if xmp_exif['Orientation'] != file_exif['Orientation']:
        print(f"{fname}")
        command = f"exiftool -P -overwrite_original -orientation#={xmp_exif['Orientation']} {image_path}"
        if args.dry_run != True:
            print(f"  executing: {command}")
            os.system(command)

parser = argparse.ArgumentParser(description="Organize files based on EXIF date.")
parser.add_argument("source", help="Source to scan for files", nargs="+")
parser.add_argument("--dry-run", help="Don't perform actions", action="store_true")

args = parser.parse_args()

with ExifTool() as e:
    for source in args.source:
        if os.path.isfile(source):
            process_file(os.path.abspath(source), args)
        elif os.path.isdir(source):
            for dirpath, dirs, files in os.walk(source):
                for filename in files:
                    fname = os.path.join(dirpath, filename)
                    process_file(fname, args)
