"""Fixture headers: raw ustar names plus supported local PAX metadata, no charset extension."""
import tarfile


class FixtureInfo(tarfile.TarInfo):
    def tobuf(self, format=tarfile.PAX_FORMAT, encoding=tarfile.ENCODING, errors="surrogateescape"):
        # Python's PAX writer adds hdrcharset=BINARY for surrogateescaped names.
        # These short fixture names fit raw ustar fields. GNU ordinary headers
        # would additionally introduce atime/ctime fields (ctime is unsupported).
        header = super().tobuf(tarfile.USTAR_FORMAT, encoding, errors)
        if not self.pax_headers:
            return header
        records = bytearray()
        for key, value in self.pax_headers.items():
            assert key != "hdrcharset"
            body = key.encode("ascii") + b"=" + value.encode(encoding, "surrogateescape") + b"\n"
            length = len(body) + 2
            while len(str(length)) + 1 + len(body) != length:
                length = len(str(length)) + 1 + len(body)
            records.extend(str(length).encode("ascii") + b" " + body)
        pax = tarfile.TarInfo("././@PaxHeader")
        pax.type, pax.size = tarfile.XHDTYPE, len(records)
        return (pax.tobuf(tarfile.USTAR_FORMAT, encoding, errors) + records
                + bytes((-len(records)) % tarfile.BLOCKSIZE) + header)
