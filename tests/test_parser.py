from __future__ import annotations

import unittest

from winespexceptiondecoder.parser import parse_log


ESP8266_LOG = """
Exception (28):
epc1=0x40201b74 excvaddr=0x00000000 depc=0x00000000

last failed alloc call: 40201234(128)
>>>stack>>>
ctx: cont
sp: 3ffffd20 end: 3fffffc0 offset: 01a0
3ffffec0:  40201010 40202020 40100100 00000000
<<<stack<<<
"""

ESP32_LOG = """
Guru Meditation Error: Core  1 panic'ed (LoadProhibited). Exception was unhandled.
PC      : 0x400d1234  PS      : 0x00060030  A0      : 0x800d5678
EXCVADDR: 0x00000004
Backtrace: 0x400d1234:0x3ffb1f20 0x400d5678:0x3ffb1f40 0x40081234:0x3ffb1f60
"""


class ParserTests(unittest.TestCase):
    def test_parse_esp8266_log(self) -> None:
        parsed = parse_log(ESP8266_LOG)
        self.assertEqual(parsed.exception.code, 28)
        self.assertEqual(parsed.registers["PC"].address, "40201b74")
        self.assertEqual(parsed.registers["EXCVADDR"].address, "00000000")
        self.assertEqual(parsed.allocation_failure.size, 128)
        self.assertEqual(parsed.stack_addresses, ["40201010", "40202020", "40100100"])

    def test_parse_esp32_backtrace(self) -> None:
        parsed = parse_log(ESP32_LOG)
        self.assertEqual(parsed.panic_reason, "LoadProhibited")
        self.assertEqual(parsed.registers["PC"].address, "400d1234")
        self.assertEqual(parsed.registers["EXCVADDR"].address, "00000004")
        self.assertEqual(parsed.backtrace_addresses, ["400d1234", "400d5678", "40081234"])

    def test_parse_mixed_noise(self) -> None:
        parsed = parse_log("noise line\nBacktrace: 0x400d1234:0x0\nmore noise")
        self.assertEqual(parsed.backtrace_addresses, ["400d1234"])
        self.assertIsNone(parsed.exception)


if __name__ == "__main__":
    unittest.main()
