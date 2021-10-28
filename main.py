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
import re
from math import sin, cos, sqrt, atan2, radians

TOKEN = None
HOST = None
ALBUMS = None
PHOTOS_TO_ALBUMS = {}

# exiftool usage from here: https://stackoverflow.com/questions/10075115/call-exiftool-from-a-python-script
class ExifTool(object):

    sentinel = "{ready}\n"

    def __init__(self, executable="/usr/bin/exiftool"):
        self.executable = executable

    def __enter__(self):
        self.process = subprocess.Popen(
            [self.executable, "-stay_open", "True", "-@", "-"],
            universal_newlines=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.process.stdin.write("-stay_open\nFalse\n")
        self.process.stdin.flush()

    def execute(self, *args):
        args = args + ("-execute\n",)
        self.process.stdin.write(str.join("\n", args))
        self.process.stdin.flush()
        output = ""
        fd = self.process.stdout.fileno()
        while not output.endswith(self.sentinel):
            output += os.read(fd, 4096).decode("utf-8")
        return output[: -len(self.sentinel)]

    def get_metadata(self, *filenames):
        return json.loads(self.execute("-G2", "-j", "-a", *filenames))

def login(username: str, password: str):
    response = requests.post(f'{HOST}/api/v1/session', json={
        'username': username,
        'password': password
    }).json()

    return response['id']

# use a buffer to help limit memory usage
def get_file_sha1(path: str):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    # md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            # md5.update(data)
            sha1.update(data)

    return sha1.hexdigest()

def geotag_photo(photo, exif, photo_id: str, force=False):
    lat = None
    lon = None

    if 'Location:GPSLatitude' in exif:
        lat_ref = exif['Location:GPSLatitudeRef'] if 'Location:GPSLatitudeRef' in exif else 'N'
        lat = extract_coordinates(exif['Location:GPSLatitude'])
        if lat is not None:
            if lat_ref[0].upper() == 'S':
                lat = lat * -1.0

    if 'Location:GPSLongitude' in exif:
        lat_ref = exif['Location:GPSLongitudeRef'] if 'Location:GPSLongitudeRef' in exif else 'E'
        lon = extract_coordinates(exif['Location:GPSLongitude'])
        if lon is not None:
            if lat_ref[0].upper() == 'W':
                lon = lon * -1.0

    if photo['Lat'] == lat and photo['Lng'] == lon:
        return

    if lat is not None and lon is not None:
        if distance_delta(lat, lon, photo['Lat'], photo['Lng']) > 1 or force == True:
            print(f'  Geotagging file {photo_id} with GPS: {lat},{lon} (previous: {photo["Lat"]},{photo["Lng"]})')
            return requests.put(f'{HOST}/api/v1/photos/{photo_id}', headers={
                'x-session-id': TOKEN,
            }, json={
                'Lat': lat,
                'Lng': lon,
                'PlaceSrc': 'manual',
            }).json()

# from https://stackoverflow.com/questions/19412462/getting-distance-between-two-points-based-on-latitude-longitude
def distance_delta(lat1, lon1, lat2, lon2):
    # approximate radius of earth in km
    R = 6373.0

    lat1 = radians(lat1)
    lon1 = radians(lon1)
    lat2 = radians(lat2)
    lon2 = radians(lon2)

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c

def add_label(id: str, tag: str):
    return requests.post(f'{HOST}/api/v1/photos/{id}/label', headers={
        'x-session-id': TOKEN,
    }, json={
        'Name': tag,
        'Priority': 10,
    }).json()

def get_albums(retval = [], offset = 0):
    response = requests.get(f'{HOST}/api/v1/albums', headers={
        'x-session-id': TOKEN,
    }, params={
        "count": 1000,
        "offset": offset,
        "q": "",
        "category": "",
        "type": "album",
    }).json()

    retval = retval + response
    if len(response) != 0:
        return get_albums(retval, len(response))

    return retval

def create_album(name):
    print(f"  Creating album {name}")
    response = requests.post(f'{HOST}/api/v1/albums', headers={
        'x-session-id': TOKEN,
    }, json={
        'Title': name,
        'Favorite': False,
    }).json()

    global ALBUMS
    ALBUMS = ALBUMS + [response]

    return response

def add_photos_to_album(album_id, photos):
    return requests.post(f'{HOST}/api/v1/albums/{album_id}/photos', headers={
        'x-session-id': TOKEN,
    }, json={
        'photos': photos,
    }).json()

def extract_coordinates(value):
    if type(value) == int or type(value) == float:
        return value
    r = re.search(r'^([0-9.]+) deg ([0-9.]+)\' ([0-9.]+)"', value)
    if r is not None:
        return float(r.groups()[0]) + (float(r.groups()[1]) / 60) + (float(r.groups()[2]) / 3600)

    return None

def get_photo(filepath):
    try:
        file_hash = get_file_sha1(filepath)
        existing_photo = requests.get(f'{HOST}/api/v1/files/{file_hash}', headers={
            'x-session-id': TOKEN,
        }).json()

        photo_id = existing_photo['PhotoUID']
        photo = requests.get(f'{HOST}/api/v1/photos/{photo_id}', headers={
            'x-session-id': TOKEN,
        }).json()

        return photo
    except:
        # photo likely doesn't exist in photoprism
        return None

def process_file(fname, args):
    image_path, extension = os.path.splitext(fname)

    # only process XMP sidecars
    if extension.lower() != '.xmp':
        # manually add specified labels to found photos
        if args.labels is not None:
            photo = get_photo(fname)
            if photo is None:
                return

            print(f"Processing {fname}")

            photo_id = photo['UID']

            for label in args.labels.split(','):
                found = False
                for existing_label in photo['Labels']:
                    if existing_label['Label']['Name'].lower() == label.lower():
                        found = True
                        break
                if found == False:
                    print(f'  Adding tag: {label}')
                    add_label(photo_id, label)

        return

    if not os.path.isfile(image_path):
        return

    photo = get_photo(image_path)
    photo_id = photo['UID']

    print(f"Processing {fname}")

    # safeguard, don't touch files that are too new
    mtime = os.path.getmtime(fname)
    if datetime.now().timestamp() - mtime < 60:
        print("  File is too new. Skipping.")
        return

    exif = e.get_metadata(fname)[0]

    if args.labels_only == False:
        geotag_photo(photo, exif, photo_id, args.force)

    if args.geo_only == False:
        tags = []
        if 'Image:TagsList' in exif:
            tags = exif['Image:TagsList']
        elif 'Image:TagsList' in exif:
            tags = exif['Image:TagsList']

        if isinstance(tags, str):
            tags = [tags]

        if len(tags) > 0:
            for tag in tags:
                nested_tags = tag.split('/')

                if nested_tags[0] == 'Albums':
                    if len(nested_tags) == 1:
                        continue

                    album_name = nested_tags[1]

                    global ALBUMS
                    if ALBUMS is None:
                        ALBUMS = get_albums()

                    album_id = None
                    for album in ALBUMS:
                        if album['Title'] == album_name:
                            album_id = album['UID']
                            break

                    if album_id is None:
                        album = create_album(album_name)
                        album_id = album['UID']

                    if album_id not in PHOTOS_TO_ALBUMS:
                        PHOTOS_TO_ALBUMS[album_id] = []

                    PHOTOS_TO_ALBUMS[album_id].append(photo_id)
                    continue

                if args.nested_labels == False:
                    nested_tags = [nested_tags.pop()]

                for nested_tag in nested_tags:
                    # check if it already exists
                    found = False
                    for existing_label in photo['Labels']:
                        if existing_label['Label']['Name'].lower() == nested_tag.lower():
                            found = True
                            break
                    if found == False or args.force == True:
                        print(f'  Adding tag: {nested_tag}')
                        add_label(photo_id, nested_tag.strip())

parser = argparse.ArgumentParser(description="Update Photoprism metadata with tags and GPS from XMP sidecars")
parser.add_argument("source", help="Source to scan for files", nargs="+")
parser.add_argument(
    "-u", "--username", help="Photoprism username", default=os.getenv("PHOTOPRISM_USERNAME", default="admin")
)
parser.add_argument(
    "-p", "--password", help="Photoprism password", default=os.getenv("PHOTOPRISM_PASSWORD", default="insecure")
)
parser.add_argument(
    "-t", "--token", help="Photoprism token", default=os.getenv("PHOTOPRISM_TOKEN")
)
parser.add_argument(
    "--host", help="Photoprism URL", default=os.getenv("PHOTOPRISM_HOST")
)
parser.add_argument(
    "--geo-only", help="Only perform geotagging", action="store_true"
)
parser.add_argument(
    "--labels-only", help="Only add labels", action="store_true"
)
parser.add_argument(
    "--labels", help="Only add labels"
)
parser.add_argument(
    "--force", help="Force update of all metadata", action="store_true"
)
parser.add_argument(
    "--nested-labels", help="Apply all nested labels", action="store_true"
)

args = parser.parse_args()

if not args.host:
    print("Please provide Photoprism host URL")
    quit()

HOST = args.host.rstrip('/')

TOKEN = args.token

if args.token is None and args.username and not args.password:
    args.password = getpass.getpass('Password: ')

if TOKEN is None and not args.username:
    print("Must provide token or username and password")
    quit()

if args.username and args.password:
    TOKEN = login(args.username, args.password)

with ExifTool() as e:
    for source in args.source:
        if os.path.isfile(source):
            process_file(os.path.abspath(source), args)
        elif os.path.isdir(source):
            for dirpath, dirs, files in os.walk(source):
                for filename in files:
                    fname = os.path.join(dirpath, filename)
                    process_file(fname, args)

for album_id, photos in PHOTOS_TO_ALBUMS.items():
    if len(photos) > 0:
        print(f"Adding {len(photos)} to album {album_id}")
        add_photos_to_album(album_id, photos)
