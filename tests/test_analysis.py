from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from winespexceptiondecoder.analysis import build_report
from winespexceptiondecoder.analysis import render_report
from winespexceptiondecoder.models import DecodeRequest, DecodedAddress


LOG = """
Exception (28):
epc1=0x40201b74 excvaddr=0x00000000
>>>stack>>>
40201010 40202020
<<<stack<<<
"""

ESP32_GURU_LOG = """
Guru Meditation Error: Core  0 panic'ed (Unhandled debug exception). Debug exception reason: Stack canary watchpoint triggered (tiT)
PC      : 0x4018a6ff  PS      : 0x00060d36
EXCVADDR: 0x00000000
Backtrace: 0x4018a6fc:0x3ffbc810 0x40190b2a:0x3ffbcbb0 0x400dd60d:0x3ffbcbf0
"""


class AnalysisTests(unittest.TestCase):
    def test_generates_null_pointer_hint(self) -> None:
        report = build_report(DecodeRequest(raw_log=LOG, elf_path=None, gdb_path=None))
        self.assertTrue(any("null-pointer" in hint for hint in report.hints))
        self.assertTrue(any("No ELF file selected" in warning for warning in report.warnings))

    def test_decodes_frames_when_tools_exist(self) -> None:
        fake_decoded = DecodedAddress(
            address="40201010",
            symbol="crash_here()",
            file_path="/tmp/source.cpp",
            line_number=99,
        )
        with patch("winespexceptiondecoder.analysis.decode_address", return_value=fake_decoded), patch(
            "winespexceptiondecoder.analysis.auto_detect_gdb",
            return_value="auto-gdb",
        ):
            report = build_report(DecodeRequest(raw_log=LOG, elf_path="firmware.elf", gdb_path="manual-gdb"))
        self.assertEqual(report.frames[0].decoded.symbol, "crash_here()")

    def test_uses_scanned_elf_when_explicit_path_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            elf_path = Path(tmpdir) / "scan" / "firmware.elf"
            elf_path.parent.mkdir()
            elf_path.write_text("", encoding="utf-8")

            fake_decoded = DecodedAddress(address="40201010", symbol="crash_here()")
            with patch("winespexceptiondecoder.analysis.decode_address", return_value=fake_decoded):
                report = build_report(
                    DecodeRequest(
                        raw_log=LOG,
                        elf_path=None,
                        elf_base_path=str(Path(tmpdir)),
                        gdb_path="manual-gdb",
                    )
                )

        self.assertEqual(report.resolved_elf_path, str(elf_path))
        self.assertEqual(report.elf_candidates, [str(elf_path)])
        self.assertEqual(report.frames[0].decoded.symbol, "crash_here()")

    def test_warns_when_scanned_base_path_has_no_elf(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report = build_report(
                DecodeRequest(
                    raw_log=LOG,
                    elf_path=None,
                    elf_base_path=tmpdir,
                    gdb_path=None,
                )
            )

        self.assertTrue(any("No ELF files were found under the base path" in warning for warning in report.warnings))

    def test_uses_cached_elf_without_rescanning(self) -> None:
        fake_decoded = DecodedAddress(address="40201010", symbol="cached_symbol()")
        with patch("winespexceptiondecoder.analysis.decode_address", return_value=fake_decoded), patch(
            "winespexceptiondecoder.analysis.find_elf_candidates",
            side_effect=AssertionError("scan should not run"),
        ):
            report = build_report(
                DecodeRequest(
                    raw_log=LOG,
                    elf_path=None,
                    elf_base_path="D:/scan-root",
                    cached_elf_path="D:/scan-root/cached.elf",
                    gdb_path="manual-gdb",
                )
            )

        self.assertEqual(report.resolved_elf_path, "D:/scan-root/cached.elf")
        self.assertEqual(report.frames[0].decoded.symbol, "cached_symbol()")

    def test_render_report_uses_guru_meditation_summary(self) -> None:
        report = build_report(DecodeRequest(raw_log=ESP32_GURU_LOG, elf_path=None, gdb_path=None))
        rendered = render_report(report)
        self.assertIn("Detected issue : Unhandled debug exception", rendered)
        self.assertIn("Debug reason   : Stack canary watchpoint triggered", rendered)
        self.assertIn("Frames decoded : 3", rendered)


if __name__ == "__main__":
    unittest.main()
