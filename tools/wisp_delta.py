#!/usr/bin/env python3
"""Reproduce exact signed APK bytes using unchanged ZIP payloads and bounded zlib literals."""
import argparse
import hashlib
import io
from pathlib import Path
import struct
import zipfile
import zlib

MAGIC = b'WISPDLT1'
FORMAT = 'wisp-zip-delta-v1'
MAX_BYTES = 150 * 1024 * 1024
LITERAL = 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payloads(data):
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            if entry.filename in result:
                raise ValueError('Duplicate ZIP entry')
            header = struct.unpack_from('<4s5H3I2H', data, entry.header_offset)
            if header[0] != b'PK\x03\x04':
                raise ValueError('Bad ZIP local header')
            start = entry.header_offset + 30 + header[-2] + header[-1]
            end = start + entry.compress_size
            if not 0 <= start <= end <= len(data):
                raise ValueError('Invalid ZIP payload')
            result[entry.filename] = (start, end)
    return result


def create(base, target):
    if not 0 < len(base) <= MAX_BYTES or not 0 < len(target) <= MAX_BYTES:
        raise ValueError('Invalid APK size')
    old = payloads(base)
    spans = []
    for name, (start, end) in payloads(target).items():
        previous = old.get(name)
        if previous and end - start >= 1024 and target[start:end] == base[previous[0]:previous[1]]:
            spans.append((start, end, previous[0]))
    spans.sort()
    commands = []
    cursor = 0

    def literal(start, end):
        for offset in range(start, end, LITERAL):
            raw = target[offset:min(offset + LITERAL, end)]
            zipped = zlib.compress(raw, 9)
            commands.append(b'\x01' + struct.pack('>II', len(raw), len(zipped)) + zipped)

    for start, end, source in spans:
        if start < cursor:
            raise ValueError('Overlapping ZIP payloads')
        literal(cursor, start)
        commands.append(b'\x00' + struct.pack('>QI', source, end - start))
        cursor = end
    literal(cursor, len(target))
    if not 0 < len(commands) <= 100000:
        raise ValueError('Too many operations')
    return (MAGIC + struct.pack('>QQ', len(base), len(target)) + hashlib.sha256(base).digest() +
            hashlib.sha256(target).digest() + struct.pack('>I', len(commands)) + b''.join(commands))


def apply(base, patch):
    """Independent publisher replay; size bounds also limit malformed compressed data."""
    stream = io.BytesIO(patch)

    def read(n):
        b = stream.read(n)
        if len(b) != n:
            raise ValueError('Truncated patch')
        return b

    if read(8) != MAGIC:
        raise ValueError('Unknown patch format')
    base_size, target_size = struct.unpack('>QQ', read(16))
    if base_size != len(base) or not 0 < target_size <= MAX_BYTES:
        raise ValueError('Invalid patch sizes')
    if read(32) != hashlib.sha256(base).digest():
        raise ValueError('Wrong base APK')
    target_hash = read(32)
    count, = struct.unpack('>I', read(4))
    if not 0 < count <= 100000:
        raise ValueError('Invalid operation count')
    output = bytearray()
    for _ in range(count):
        kind = read(1)
        if kind == b'\x00':
            offset, length = struct.unpack('>QI', read(12))
            if length <= 0 or offset + length > base_size or len(output) + length > target_size:
                raise ValueError('Invalid copy range')
            output.extend(base[offset:offset + length])
        elif kind == b'\x01':
            length, size = struct.unpack('>II', read(8))
            if not 0 < length <= LITERAL or not 0 < size <= LITERAL + 1024 or len(output) + length > target_size:
                raise ValueError('Invalid literal size')
            inflater = zlib.decompressobj()
            decoded = inflater.decompress(read(size), length + 1)
            if len(decoded) != length or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
                raise ValueError('Invalid compressed literal')
            output.extend(decoded)
        else:
            raise ValueError('Unknown operation')
    if len(output) != target_size or stream.read(1) or hashlib.sha256(output).digest() != target_hash:
        raise ValueError('Target APK mismatch')
    return bytes(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve() in {args.base.resolve(), args.target.resolve()}:
        parser.error('Output must not overwrite an APK')
    base, target = args.base.read_bytes(), args.target.read_bytes()
    patch = create(base, target)
    if apply(base, patch) != target:
        raise ValueError('Replay failed')
    if len(patch) >= len(target):
        parser.error('No saving: publish only the full APK')
    args.output.write_bytes(patch)
    print(f'Verified patch: {len(patch)} / {len(target)} bytes ({100 * len(patch) / len(target):.1f}%)')
    print('Patch SHA-256: ' + digest(patch))
