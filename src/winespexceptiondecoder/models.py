from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DecodeRequest:
    raw_log: str
    elf_path: str | None
    elf_base_path: str | None = None
    cached_elf_path: str | None = None
    gdb_path: str | None = None


@dataclass(slots=True)
class ExceptionInfo:
    code: int
    name: str


@dataclass(slots=True)
class RegisterValue:
    name: str
    address: str


@dataclass(slots=True)
class AllocationFailure:
    address: str
    size: int


@dataclass(slots=True)
class ParsedLog:
    raw_log: str
    exception: ExceptionInfo | None = None
    panic_reason: str | None = None
    debug_reason: str | None = None
    registers: dict[str, RegisterValue] = field(default_factory=dict)
    allocation_failure: AllocationFailure | None = None
    stack_addresses: list[str] = field(default_factory=list)
    backtrace_addresses: list[str] = field(default_factory=list)
    all_addresses: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DecodedAddress:
    address: str
    symbol: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    raw_line: str | None = None
    error: str | None = None


@dataclass(slots=True)
class DecodedFrame:
    address: str
    context: str
    decoded: DecodedAddress | None = None


@dataclass(slots=True)
class DecodeReport:
    request: DecodeRequest
    parsed_log: ParsedLog
    resolved_elf_path: str | None = None
    elf_candidates: list[str] = field(default_factory=list)
    frames: list[DecodedFrame] = field(default_factory=list)
    decoded_registers: dict[str, DecodedAddress] = field(default_factory=dict)
    decoded_allocation: DecodedAddress | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
