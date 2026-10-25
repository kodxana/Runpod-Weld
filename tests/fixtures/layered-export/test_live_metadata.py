"""Linux/root tests for the same static helper used in Docker acceptance."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from live_metadata import assert_metadata, compile_probe, decode_probe, probe_input


class LiveMetadataTests(unittest.TestCase):
    def test_precise_nonmutating_probe_and_fractional_corruption(self):
        with tempfile.TemporaryDirectory(prefix="layered-live-metadata-") as directory:
            root = Path(directory)
            helper = compile_probe(root / "helper")
            fixture = root / "fixture"
            fixture.mkdir()
            file = fixture / "file"
            file.write_bytes(b"payload")
            os.setxattr(file, "user.layered", b"exact\x00bytes")
            os.setxattr(file, "security.capability", struct.pack("<5I", 0x02000001, 1024, 0, 0, 0))
            alias = fixture / "alias"
            os.link(file, alias)
            link = fixture / "link"
            link.symlink_to("file")
            raw = fixture / os.fsdecode(b"raw-\xff")
            raw.write_bytes(b"raw")
            paths = [str(p) for p in [fixture, file, alias, link, raw]]
            for path in paths:
                os.utime(path, ns=(1700000000123456789, 1700000000250000001), follow_symlinks=False)
            before = {p: os.lstat(p) for p in paths}
            expected = {p: {"mode": s.st_mode, "uid": s.st_uid, "gid": s.st_gid,
                            "mtime_ns": s.st_mtime_ns, "xattrs": {
                                k: os.getxattr(p, k, follow_symlinks=False).hex()
                                for k in os.listxattr(p, follow_symlinks=False)}} for p, s in before.items()}

            def observe():
                return decode_probe(subprocess.check_output([str(helper)], input=probe_input(paths)))

            first, repeated = observe(), observe()
            assert_metadata(first, expected)
            self.assertEqual(first, repeated)
            for path in paths:
                self.assertEqual(first[path]["atime_ns"], before[path].st_atime_ns)
                self.assertEqual(os.lstat(path).st_atime_ns, before[path].st_atime_ns)
                self.assertEqual(os.lstat(path).st_ctime_ns, before[path].st_ctime_ns)
            self.assertEqual(first[str(file)]["ino"], first[str(alias)]["ino"])
            # Change only ONE fractional nanosecond on a real inode; detection
            # must come through the helper, not a fabricated parsed response.
            os.utime(file, ns=(before[str(file)].st_atime_ns, before[str(file)].st_mtime_ns + 1))
            with self.assertRaisesRegex(AssertionError, "mtime_ns"):
                assert_metadata(observe(), expected)


if __name__ == "__main__":
    unittest.main()
