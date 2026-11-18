import argparse
import struct
from pathlib import Path

MAGIC = bytes.fromhex('112233445566778899aabbccddeeff75')
FIXED = bytes.fromhex('cde0e507f174e7c1bc4ab32993c220cc9820')
POLY = (1 << 233) | (1 << 74) | 1
MASK = (1 << 233) - 1


def gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        carry = a >> 232
        a = (a << 1) & MASK
        if carry:
            a ^= (1 << 74) | 1
    return result


def gf_inv(a: int) -> int:
    if not a:
        raise ZeroDivisionError
    u, v, g1, g2 = a, POLY, 1, 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            g1, g2 = g2, g1
            shift = -shift
        u ^= v << shift
        g1 ^= g2 << shift
    return g1 & MASK if g1.bit_length() <= 233 else gf_reduce(g1)


def gf_reduce(a: int) -> int:
    while a.bit_length() > 233:
        a ^= POLY << (a.bit_length() - 234)
    return a


def point_add(p: tuple[int, int] | None, q: tuple[int, int] | None):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if y1 != y2:
            return None
        if x1 == 0:
            return None
        lam = x1 ^ gf_mul(y1, gf_inv(x1))
        x3 = gf_mul(lam, lam) ^ lam
        y3 = gf_mul(x1, x1) ^ gf_mul(lam ^ 1, x3)
    else:
        lam = gf_mul(y1 ^ y2, gf_inv(x1 ^ x2))
        x3 = gf_mul(lam, lam) ^ lam ^ x1 ^ x2
        y3 = gf_mul(lam, x1 ^ x3) ^ x3 ^ y1
    return x3, y3


def point_mul(k: int, p: tuple[int, int]):
    result = None
    while k:
        if k & 1:
            result = point_add(result, p)
        p = point_add(p, p)
        k >>= 1
    return result


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    result = bytearray(data)
    for pos in range(len(result)):
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        result[pos] ^= s[(s[i] + s[j]) & 255]
    return bytes(result)


def folded_checksum(data: bytes) -> bytes:
    out = bytearray(20)
    for i, value in enumerate(data):
        out[i % 20] ^= value
    return bytes(value ^ 0xff for value in out)


def decode(blob: bytes) -> bytes:
    assert blob[:16] == MAGIC
    declared, header_size = struct.unpack_from('<II', blob, 0x10)
    assert declared == len(blob) and header_size == 0x200
    assert blob[0x18:0x2a] == FIXED
    header = bytearray(blob[:0x200])
    header[0x2a:0x1ec] = rc4(header[0x2a:0x1ec], header[0x1ee:0x1fe])
    assert folded_checksum(header[0x2a:0x1ec]) == header[0x1ec:0x200]
    assert header[0x3a] == 3
    assert struct.unpack_from('<H', header, 0x97)[0] == 0xdd
    assert header[0x176] == 2
    assert header[0x19f] == ord('m')
    x = int.from_bytes(header[0x5b:0x79], 'little')
    y = int.from_bytes(header[0x79:0x97], 'little')
    assert gf_mul(y, y) ^ gf_mul(x, y) == gf_mul(gf_mul(x, x), x) ^ 1
    mask = header[0x18f:0x19f] + header[0x18f:0x19d]
    scalar = int.from_bytes(bytes(a ^ b for a, b in zip(header[0x1ce:0x1ec], mask)), 'little')
    point = point_mul(scalar, (x, y))
    assert point is not None
    sx, sy = point
    shared = sx.to_bytes(30, 'little')[:29] + sy.to_bytes(30, 'little')[:3]
    session_key = bytes(a ^ b for a, b in zip(header[0x3b:0x5b], shared))
    key = (session_key[16:32] +
           bytes.fromhex('73fbecabd97d674e80224f4423d30dfe') +
           session_key[0:16] +
           bytes.fromhex('29230581e0ee8446ac7c0ee2b2e36c5d'))
    return rc4(blob[0x200:], key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    args.destination.write_bytes(decode(args.source.read_bytes()))


if __name__ == '__main__':
    main()
