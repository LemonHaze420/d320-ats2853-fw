from pathlib import Path
import argparse
import re
import struct
import zlib

import decode
import unwrap

IMAGES = {
    "mbrec.bin": b"ACTHHTCA",
    "param.bin": b"ACPT",
    "sdfs.bin": b"sdfs.bin",
    "zephyr.bin": b"ACTHHTCA",
}


def name83(entry):
    base = entry[:8].decode("ascii").rstrip()
    ext = entry[8:11].decode("ascii").rstrip()
    return base + ("." + ext if ext else "")


def long_name(entries):
    raw = b"".join(e[1:11] + e[14:26] + e[28:32]
                   for e in sorted(entries, key=lambda e: e[0] & 31))
    return raw.decode("utf-16-le").split("\0", 1)[0].rstrip("\uffff")


def extract(source, destination):
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("destination is not empty")
    data = source.read_bytes()
    if data[:8] != b"ACTTEST0":
        raise ValueError("invalid firmware signature")
    count, length, crc = (struct.unpack_from("<I", data, offset)[0]
                          for offset in (0x0c, 0x14, 0x18))
    if not 1 <= count <= 14 or length != len(data) or zlib.crc32(data[512:]) != crc:
        raise ValueError("invalid firmware directory")

    outer = {}
    for index in range(count):
        raw_name, offset, size, _, crc = struct.unpack_from("<16s4I", data, 0x20 + index * 32)
        name = raw_name.split(b"\0", 1)[0].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in outer or offset < 512 or offset + size > len(data):
            raise ValueError("invalid outer entry")
        blob = data[offset:offset + size]
        if zlib.crc32(blob) != crc:
            raise ValueError(name)
        outer[name] = blob

    att = outer.pop("attdfu.fw")
    if not att.startswith(b"100TMFWFSTCA"):
        raise ValueError("invalid attdfu.fw")
    nested = {}
    lfn = []
    for offset in range(0x203010, min(len(att), 0x205010), 32):
        entry = att[offset:offset + 32]
        if len(entry) < 32 or entry[0] == 0:
            break
        if entry[0] == 0xe5:
            lfn = []
            continue
        if entry[11] == 0x0f:
            lfn.append(entry)
            continue
        name = (long_name(lfn) if lfn else name83(entry)).removesuffix("~0")
        lfn = []
        if entry[11] & 0x18:
            continue
        cluster = (struct.unpack_from("<H", entry, 20)[0] << 16) | struct.unpack_from("<H", entry, 26)[0]
        size = struct.unpack_from("<I", entry, 28)[0]
        if cluster < 2 or not size:
            continue
        start = 0x203010 + (cluster - 2) * 4096
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in nested or start + size > len(att):
            raise ValueError("invalid nested entry")
        nested[name] = att[start:start + size]

    files = {}
    for name, blob in outer.items():
        decoded = decode.decode(blob) if name in IMAGES else blob
        if name in IMAGES and not decoded.startswith(IMAGES[name]):
            raise ValueError(name)
        files[name] = decoded
    for name, blob in nested.items():
        decoded = bytes(value ^ 0x38 for value in blob)
        if name in outer:
            if decoded != outer[name]:
                raise ValueError(name)
        elif name == "sdfs_ori.bin":
            if decoded != files["sdfs.bin"]:
                raise ValueError(name)
        elif name == "FIRMWARE":
            if decoded != b"DUMMY FILE for card product":
                raise ValueError(name)
        else:
            if blob.startswith(unwrap.MAGIC):
                decoded = unwrap.decode(blob)
                if not (decoded.startswith(b"MZ") or decoded.startswith(bytes.fromhex("03f30d0a"))):
                    raise ValueError(name)
            files[name] = decoded

    sdfs = files["sdfs.bin"]
    count, size = struct.unpack_from("<II", sdfs, 12)
    if size != len(sdfs) or not 1 <= count <= 256:
        raise ValueError("invalid sdfs.bin")
    for index in range(1, count):
        entry = sdfs[index * 32:(index + 1) * 32]
        name = entry[:12].split(b"\0", 1)[0].decode("ascii")
        offset, length = struct.unpack_from("<II", entry, 12)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in files or offset < count * 32 or offset + length > len(sdfs):
            raise ValueError("invalid sdfs entry")
        files[name] = sdfs[offset:offset + length]

    destination.mkdir(parents=True, exist_ok=True)
    for name, blob in files.items():
        (destination / name).write_bytes(blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    extract(args.firmware, args.destination)
