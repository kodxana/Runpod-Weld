"""Small offline regressions for the package smoke's independent assertions."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from release_package import digest, read_image, verify_install


class PackageAssertions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def image(self, compression=None, content=b'image', compressed_diff=False):
        blobs = self.root/'blobs/sha256'
        blobs.mkdir(parents=True, exist_ok=True)

        def blob(data, media):
            checksum = hashlib.sha256(data).hexdigest()
            (blobs/checksum).write_bytes(data)
            return {'digest': 'sha256:'+checksum, 'size': len(data), 'mediaType': media}

        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as tar:
            member = tarfile.TarInfo('tmp/result')
            member.size = len(content)
            member.uid = member.gid = 65534
            tar.addfile(member, io.BytesIO(content))
        raw = data.getvalue()
        payload = gzip.compress(raw, mtime=0) if compression else raw
        layer = blob(payload, 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if compression else ''))
        diff = 'sha256:'+hashlib.sha256(payload if compressed_diff else raw).hexdigest()
        config = blob(json.dumps({'rootfs': {'type': 'layers', 'diff_ids': [diff, diff]},
                                  'history': [{}, {}]}).encode(), 'config')
        manifest = blob(json.dumps({'config': config, 'layers': [layer, layer]}).encode(), 'manifest')
        (self.root/'index.json').write_text(json.dumps({'manifests': [manifest]}))
        return blobs/layer['digest'].split(':')[1]

    def test_raw_and_gzip_use_uncompressed_diff_ids(self):
        for compression in (None, 'gzip'):
            with self.subTest(compression=compression):
                self.image(compression)
                _, files = read_image(self.root, compression, b'synthetic-secret')
                self.assertEqual(files['tmp/result'], (b'image', 65534, 65534))

    def test_compressed_digest_is_not_a_diff_id(self):
        self.image('gzip', compressed_diff=True)
        with self.assertRaises(AssertionError):
            read_image(self.root, 'gzip', b'synthetic-secret')

    def test_corrupted_layer_is_rejected(self):
        layer = self.image()
        layer.write_bytes(b'corrupt')
        with self.assertRaises(AssertionError):
            read_image(self.root, None, b'synthetic-secret')

    def test_secret_in_compressed_payload_is_rejected(self):
        self.image('gzip', content=b'synthetic-secret')
        with self.assertRaises(AssertionError):
            read_image(self.root, 'gzip', b'synthetic-secret')

    def install(self):
        # A public prefix, even when the invoking shell uses umask 077.
        prefix = self.root/'prefix'
        binary = prefix/'bin/rpweld'
        metadata = prefix/'share/doc/rpweld/build-info.json'
        metadata.parent.mkdir(parents=True)
        binary.parent.mkdir()
        binary.write_bytes(b'fixture')
        binary.chmod(0o755)
        for directory in [prefix, *[p for p in prefix.rglob('*') if p.is_dir()]]:
            directory.chmod(0o755)
        info = {'version': '0.2.0', 'commit': 'a'*40, 'skopeo': 'skopeo fixture',
                'files': {'bin/rpweld': digest(binary)}}
        metadata.write_text(json.dumps(info))
        metadata.chmod(0o644)
        return binary, metadata, info

    @patch('release_package.subprocess.check_output')
    def test_version_comes_from_artifact_not_hardcoded_release(self, command):
        binary, _, info = self.install()
        version = f'rpweld 0.2.0 (build {info["commit"]})\n'
        command.side_effect = [version, version, '', 'skopeo fixture\n']
        verify_install(binary, info)
        self.assertEqual(command.call_args_list[1].kwargs['user'], 65534)

    def test_restrictive_package_directory_is_rejected(self):
        binary, _, info = self.install()
        binary.parent.parent.chmod(0o700)
        with self.assertRaises(AssertionError):
            verify_install(binary, info)

    @patch('release_package.subprocess.check_output', return_value='rpweld 0.2.0 (build wrong)\n')
    def test_wrong_build_id_is_rejected(self, command):
        binary, _, info = self.install()
        with self.assertRaises(AssertionError):
            verify_install(binary, info)

    def test_restrictive_metadata_mode_is_rejected(self):
        binary, metadata, info = self.install()
        metadata.chmod(0o600)
        with self.assertRaises(AssertionError):
            verify_install(binary, info)

    def test_installed_binary_hash_must_match_artifact(self):
        binary, _, info = self.install()
        binary.write_bytes(b'changed')
        with self.assertRaisesRegex(AssertionError, 'hash mismatch'):
            verify_install(binary, info)


if __name__ == '__main__':
    unittest.main()
