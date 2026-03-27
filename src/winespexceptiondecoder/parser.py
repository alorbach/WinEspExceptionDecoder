from __future__ import annotations

import re

from .models import AllocationFailure, ExceptionInfo, ParsedLog, RegisterValue

EXCEPTIONS = {
    0: "Illegal instruction",
    1: "SYSCALL instruction",
    2: "InstructionFetchError",
    3: "LoadStoreError",
    4: "Level1Interrupt",
    5: "Alloca",
    6: "IntegerDivideByZero",
    7: "reserved",
    8: "Privileged",
    9: "LoadStoreAlignmentCause",
    10: "reserved",
    11: "reserved",
    12: "InstrPIFDataError",
    13: "LoadStorePIFDataError",
    14: "InstrPIFAddrError",
    15: "LoadStorePIFAddrError",
    16: "InstTLBMiss",
    17: "InstTLBMultiHit",
    18: "InstFetchPrivilege",
    19: "reserved",
    20: "InstFetchProhibited",
    21: "reserved",
    22: "reserved",
    23: "reserved",
    24: "LoadStoreTLBMiss",
    25: "LoadStoreTLBMultiHit",
    26: "LoadStorePrivilege",
    27: "reserved",
    28: "LoadProhibited",
    29: "StoreProhibited",
}

_HEX_ADDR_RE = re.compile(r"\b(?:0x)?(4[0-3][0-9a-fA-F]{6})\b")
_EXCEPTION_RE = re.compile(r"Exception \(([0-9]{1,2})\):")
_PANIC_RE = re.compile(r"Guru Meditation Error:.*?\(([^)]+)\)", re.IGNORECASE)
_DEBUG_REASON_RE = re.compile(r"Debug exception reason:\s*(.+)", re.IGNORECASE)
_ALLOC_RE = re.compile(r"last failed alloc call:\s*(?:0x)?(4[0-3][0-9a-fA-F]{6})\((\d+)\)", re.IGNORECASE)
_STACK_RE = re.compile(r">>>stack>>>(.*?)<<<stack<<<", re.DOTALL | re.IGNORECASE)
_BACKTRACE_RE = re.compile(r"Backtrace:(.*)", re.IGNORECASE)
_REGISTER_PATTERNS = (
    ("PC", re.compile(r"\bPC\s*:\s*(?:0x)?([0-9a-fA-F]{8})\b")),
    ("PC", re.compile(r"\bepc1=0x([0-9a-fA-F]{8})\b", re.IGNORECASE)),
    ("EXCVADDR", re.compile(r"\bEXCVADDR\s*:\s*(?:0x)?([0-9a-fA-F]{8})\b")),
    ("EXCVADDR", re.compile(r"\bexcvaddr=0x([0-9a-fA-F]{8})\b", re.IGNORECASE)),
)


def _extract_addresses(text: str) -> list[str]:
    return [match.group(1).lower() for match in _HEX_ADDR_RE.finditer(text)]


def parse_log(raw_log: str) -> ParsedLog:
    parsed = ParsedLog(raw_log=raw_log)

    exception_match = _EXCEPTION_RE.search(raw_log)
    if exception_match:
        code = int(exception_match.group(1))
        parsed.exception = ExceptionInfo(code=code, name=EXCEPTIONS.get(code, "Unknown exception"))

    panic_match = _PANIC_RE.search(raw_log)
    if panic_match:
        parsed.panic_reason = panic_match.group(1).strip()

    debug_reason_match = _DEBUG_REASON_RE.search(raw_log)
    if debug_reason_match:
        parsed.debug_reason = debug_reason_match.group(1).strip()

    for register_name, pattern in _REGISTER_PATTERNS:
        if register_name in parsed.registers:
            continue
        match = pattern.search(raw_log)
        if match:
            parsed.registers[register_name] = RegisterValue(name=register_name, address=match.group(1).lower())

    alloc_match = _ALLOC_RE.search(raw_log)
    if alloc_match:
        parsed.allocation_failure = AllocationFailure(address=alloc_match.group(1).lower(), size=int(alloc_match.group(2)))

    stack_match = _STACK_RE.search(raw_log)
    if stack_match:
        parsed.stack_addresses = _extract_addresses(stack_match.group(1))

    backtrace_match = _BACKTRACE_RE.search(raw_log)
    if backtrace_match:
        parsed.backtrace_addresses = _extract_addresses(backtrace_match.group(1))

    ordered_addresses: list[str] = []
    seen: set[str] = set()

    for address in parsed.stack_addresses + parsed.backtrace_addresses:
        if address not in seen:
            ordered_addresses.append(address)
            seen.add(address)

    for register in parsed.registers.values():
        if register.address not in seen:
            ordered_addresses.append(register.address)
            seen.add(register.address)

    if parsed.allocation_failure and parsed.allocation_failure.address not in seen:
        ordered_addresses.append(parsed.allocation_failure.address)
        seen.add(parsed.allocation_failure.address)

    parsed.all_addresses = ordered_addresses
    return parsed
