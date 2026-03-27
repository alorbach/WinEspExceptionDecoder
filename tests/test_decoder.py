from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from winespexceptiondecoder.decoder import decode_address, find_elf_candidates, parse_gdb_line


class DecoderTests(unittest.TestCase):
    def test_parse_gdb_line(self) -> None:
        decoded = parse_gdb_line("400d1234", "0x400d1234 is in app_main() at /tmp/main.cpp:42")
        self.assertEqual(decoded.symbol, "app_main()")
        self.assertEqual(decoded.file_path, "/tmp/main.cpp")
        self.assertEqual(decoded.line_number, 42)

    def test_decode_address_missing_gdb(self) -> None:
        decoded = decode_address("missing-gdb", "missing.elf", "400d1234")
        self.assertIn("GDB not found", decoded.error)

    def test_decode_address_subprocess_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            gdb_path = Path(tmpdir) / "fake-gdb.exe"
            elf_path = Path(tmpdir) / "firmware.elf"
            gdb_path.write_text("", encoding="utf-8")
            elf_path.write_text("", encoding="utf-8")

            with patch("winespexceptiondecoder.decoder.subprocess.run", side_effect=OSError("boom")):
                decoded = decode_address(str(gdb_path), str(elf_path), "400d1234")
            self.assertEqual(decoded.error, "boom")

    def test_find_elf_candidates_returns_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            older = root / "older.elf"
            newer = root / "nested" / "newer.elf"
            newer.parent.mkdir()
            older.write_text("", encoding="utf-8")
            time.sleep(0.02)
            newer.write_text("", encoding="utf-8")

            candidates = find_elf_candidates(str(root))

        self.assertEqual(candidates[0], str(newer))
        self.assertEqual(candidates[1], str(older))


if __name__ == "__main__":
    unittest.main()
