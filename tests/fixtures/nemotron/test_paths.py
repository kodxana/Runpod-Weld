"""Small tar fixtures for the Linux-only image path contract; no image builds."""
import contextlib
import gzip
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import oracle


class ImagePaths(unittest.TestCase):
    def test_literal_backslashes_in_raw_and_gzip_layers(self):
        names = [r'usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice',
                 r'ordinary\name', r'..\literal', r'C:\literal']
        for compressed in (False, True):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w') as archive:
                    for name in names:
                        member = tarfile.TarInfo(name)
                        member.size = 7
                        archive.addfile(member, io.BytesIO(b'payload'))
                raw = stream.getvalue()
                encoded = gzip.compress(raw, mtime=0) if compressed else raw
                path = Path(directory) / 'blob'
                path.write_bytes(encoded)
                descriptor = {'digest': 'sha256:' + oracle.sha(encoded), 'size': len(encoded),
                              'mediaType': 'application/vnd.oci.image.layer.v1.tar' +
                                           ('+gzip' if compressed else '')}
                with contextlib.redirect_stdout(io.StringIO()):
                    result = oracle.Layers(oracle.Files(), dict.fromkeys(names)).scan(
                        path, descriptor, 'sha256:' + oracle.sha(raw))
                self.assertEqual([name for name, _ in result['operations']], names)
                for _, value in result['operations']:
                    self.assertEqual(value['sha256'], oracle.sha(b'payload'))

    def test_posix_traversal_absolute_nul_and_limits_remain_rejected(self):
        for name in ('../escape', '/absolute', 'ok/../escape', 'ok\\name/../../escape',
                     'nul\0name', 'x' * 4097):
            with self.subTest(name=name), self.assertRaises(oracle.Rejected):
                oracle.path_name(name, posix=True)
        self.assertEqual(oracle.path_name('./a//b', posix=True), 'a/b')
        self.assertEqual(oracle.path_name('.', posix=True), '')

    def test_source_paths_keep_portable_restrictions(self):
        for name in (r'..\escape', r'C:\absolute', r'plain\name'):
            with self.subTest(name=name), self.assertRaises(oracle.Rejected):
                oracle.path_name(name)


if __name__ == '__main__':
    unittest.main()
