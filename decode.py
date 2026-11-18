from pathlib import Path
import argparse

SEED = 0x030A93B4
TAPS = (
    (0, 5, 10, 15, 20, 25, 31),
    (0, 1, 6, 12, 16, 22, 27),
    (2, 7, 13, 23, 28),
    (3, 8, 14, 24, 29),
    (15, 25, 31, 4, 9),
    (5, 10, 26),
    (5, 12, 28),
    (6, 2, 7, 13, 3, 8, 29),
)
FEEDBACK = (0, 1, 3, 4, 6, 7, 9, 10, 11, 15, 21, 22, 25, 31)


def output_byte(state):
    return sum((sum((state >> bit) & 1 for bit in taps) & 1) << i
               for i, taps in enumerate(TAPS))


def update(state, plain):
    low = sum((state >> bit) & 1 for bit in FEEDBACK) & 1
    second = ((state & 1) ^ ((plain >> 2) & 1) ^ ((plain >> 3) & 1)
              ^ ((plain >> 4) & 1) ^ ((plain >> 5) & 1))
    return (((state & 0xfffffffe) << 1) | (second << 1) | low) & 0xffffffff


def decode(data):
    out = bytearray(len(data))
    for base in range(0, len(data), 32):
        state = SEED
        for index in range(base, min(base + 32, len(data))):
            out[index] = data[index] ^ output_byte(state)
            state = update(state, out[index])
    return bytes(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    args.destination.write_bytes(decode(args.source.read_bytes()))
