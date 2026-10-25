"""No-builder regressions for the independent replay/observation convention."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from oracle import replay, snapshot


MTIME = "1577836800.250000001"
ATIME = "1577836800.125000003"
MNS = 1577836800250000001
ANS = 1577836800125000003


def layout_at(root, layers):
    layout = root / "layout"
    blobs = layout / "blobs/sha256"
    blobs.mkdir(parents=True)
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}
    descriptors = []
    for entries in layers:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, kind, target, explicit in entries:
                member = tarfile.TarInfo(name)
                member.type, member.mode, member.mtime = kind, 0o777, 1577836800
                member.pax_headers = {"mtime": MTIME}
                if explicit:
                    member.pax_headers["atime"] = ATIME
                if kind == tarfile.REGTYPE:
                    member.size = 1
                elif kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                    member.linkname = target
                archive.addfile(member, io.BytesIO(b"x") if member.isfile() else None)
        descriptors.append(blob(buffer.getvalue(), "application/vnd.oci.image.layer.v1.tar"))
    config = blob(json.dumps({"rootfs": {"diff_ids": [d["digest"] for d in descriptors]}}).encode(),
                  "application/vnd.oci.image.config.v1+json")
    manifest = blob(json.dumps({"layers": descriptors, "config": config}).encode(),
                    "application/vnd.oci.image.manifest.v1+json")
    (layout / "index.json").write_text(json.dumps({"manifests": [manifest]}))
    return layout


class TimestampTests(unittest.TestCase):
    def test_four_entry_replay_is_deterministic_and_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            layout = layout_at(root, [[(".", tarfile.DIRTYPE, "", True),
                                      ("d", tarfile.DIRTYPE, "", False),
                                      ("f", tarfile.REGTYPE, "", False),
                                      ("link", tarfile.SYMTYPE, "f", True)]])
            trees = []
            for name in ["a", "b"]:
                replay(layout, root / name)
                trees.append(snapshot(root / name))
            self.assertEqual(set(trees[0]), {".", "d", "f", "link"})
            for name in trees[0]:
                self.assertEqual(trees[0][name]["mtime_ns"], MNS)
                self.assertEqual(trees[0][name]["atime_ns"], ANS if name in (".", "link") else MNS)
            self.assertEqual(trees[0], trees[1])

    def test_missing_root_and_omitted_link_atime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            layout = layout_at(root, [[(".", tarfile.DIRTYPE, "", True),
                                      ("f", tarfile.REGTYPE, "", True)],
                                     [("hard", tarfile.LNKTYPE, "f", False),
                                      ("link", tarfile.SYMTYPE, "f", False)]])
            replay(layout, root / "tree")
            tree = snapshot(root / "tree")
            self.assertEqual(set(tree), {".", "f", "hard", "link"})
            self.assertEqual(tree["."]["atime_ns"], ANS)
            self.assertEqual(tree["."]["mtime_ns"], MNS)
            for name in ["f", "hard", "link"]:
                self.assertEqual(tree[name]["atime_ns"], MNS)
                self.assertEqual(tree[name]["mtime_ns"], MNS)
            self.assertEqual(tree["f"]["hardlink_group"], tree["hard"]["hardlink_group"])

    def test_snapshot_captures_all_alias_metadata_before_observing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target").write_bytes(b"x")
            (root / "a").symlink_to("target")
            os.link(root / "a", root / "z", follow_symlinks=False)
            os.utime(root / "a", ns=(ANS, MNS), follow_symlinks=False)
            before = {n: (root / n).lstat() for n in ["a", "z"]}
            first = snapshot(root)
            after = {n: (root / n).lstat() for n in before}
            for name in before:
                self.assertEqual(first[name]["atime_ns"], before[name].st_atime_ns)
                self.assertEqual(first[name]["mtime_ns"], MNS)
                self.assertEqual(first[name]["target"], "target")
                self.assertEqual(after[name].st_ctime_ns, before[name].st_ctime_ns)
            # Reads may advance live atime; the next snapshot describes that new
            # state, never a secretly restored/cached version of the first view.
            second = snapshot(root)
            for name in before:
                self.assertEqual(second[name]["atime_ns"], after[name].st_atime_ns)
                self.assertEqual((root / name).lstat().st_ctime_ns, after[name].st_ctime_ns)


if __name__ == "__main__":
    unittest.main()
