import io
import struct
import unittest
import zipfile
import zlib
from wisp_delta import create, apply


def apk(changed):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('classes.dex', changed)
        z.writestr('lib/arm64-v8a/libcore.so', bytes(range(256)) * 20000)
        z.writestr('assets/config', b'unchanged' * 9000)
    return out.getvalue() + b'opaque signed trailer'


class DeltaTests(unittest.TestCase):
    def test_exact_signed_bytes_and_changed_offsets(self):
        base, target = apk(b'old dex'), apk(b'new dex, longer payload')
        patch = create(base, target)
        self.assertEqual(apply(base, patch), target)
        self.assertLess(len(patch), len(target))

    def test_changed_base_is_rejected(self):
        base, target = apk(b'old'), apk(b'new')
        with self.assertRaises(ValueError):
            apply(base[:-1] + b'x', create(base, target))

    def test_truncated_modified_and_trailing_patches_are_rejected(self):
        base, target = apk(b'old'), apk(b'new')
        p = create(base, target)
        for bad in [p[:10], p[:-1], p + b'x', b'BADMAGIC' + p[8:], p[:56] + b'x' * 32 + p[88:]]:
            with self.subTest(size=len(bad)), self.assertRaises((ValueError, zlib.error)):
                apply(base, bad)

    def test_copy_bounds_and_output_limits(self):
        base, target = apk(b'old'), apk(b'new')
        h = create(base, target)[:88] + struct.pack('>I', 1)
        for command in [b'\x00' + struct.pack('>QI', len(base), 1), b'\x00' + struct.pack('>QI', 0, len(target) + 1),
                        b'\x01' + struct.pack('>II', 2**31, 1) + b'x', b'\x7f']:
            with self.assertRaises(ValueError):
                apply(base, h + command)

    def test_compression_bomb_is_bounded(self):
        base, target = apk(b'old'), apk(b'new')
        bomb = zlib.compress(b'x' * (1024 * 1024 * 8))
        h = create(base, target)[:88] + struct.pack('>I', 1)
        with self.assertRaises(ValueError):
            apply(base, h + b'\x01' + struct.pack('>II', 16, len(bomb)) + bomb)


if __name__ == '__main__':
    unittest.main()
