from __future__ import annotations

from .decoder import auto_detect_gdb, decode_address, find_elf_candidates
from .models import DecodeReport, DecodeRequest, DecodedFrame
from .parser import parse_log


def build_report(request: DecodeRequest) -> DecodeReport:
    parsed = parse_log(request.raw_log)
    report = DecodeReport(request=request, parsed_log=parsed)

    if not request.raw_log.strip():
        report.warnings.append("No log content provided.")
        return report

    gdb_path = request.gdb_path or auto_detect_gdb()
    elf_path = request.elf_path
    if not elf_path and request.cached_elf_path:
        elf_path = request.cached_elf_path
        report.resolved_elf_path = elf_path
    elif not elf_path and request.elf_base_path:
        report.elf_candidates = find_elf_candidates(request.elf_base_path)
        if report.elf_candidates:
            elf_path = report.elf_candidates[0]
            report.resolved_elf_path = elf_path
            if len(report.elf_candidates) > 1:
                report.warnings.append(
                    f"Multiple ELF files were found under the base path. Using the newest match: {elf_path}"
                )
        else:
            report.warnings.append(
                f"No ELF files were found under the base path: {request.elf_base_path}"
            )
    elif elf_path:
        report.resolved_elf_path = elf_path

    if not gdb_path:
        report.warnings.append("No Arduino-compatible gdb was found automatically. Set it manually to decode symbols.")
    if not elf_path:
        report.warnings.append("No ELF file selected. Address extraction still works, but source resolution is unavailable.")

    decode_cache: dict[str, object] = {}

    def maybe_decode(address: str):
        if address not in decode_cache:
            if gdb_path and elf_path:
                decode_cache[address] = decode_address(gdb_path, elf_path, address)
            else:
                decode_cache[address] = None
        return decode_cache[address]

    for address in parsed.stack_addresses:
        report.frames.append(DecodedFrame(address=address, context="stack", decoded=maybe_decode(address)))

    for address in parsed.backtrace_addresses:
        report.frames.append(DecodedFrame(address=address, context="backtrace", decoded=maybe_decode(address)))

    for name, register in parsed.registers.items():
        decoded = maybe_decode(register.address)
        if decoded is not None:
            report.decoded_registers[name] = decoded

    if parsed.allocation_failure:
        decoded = maybe_decode(parsed.allocation_failure.address)
        if decoded is not None:
            report.decoded_allocation = decoded

    if parsed.exception is None:
        report.warnings.append("No ESP exception code was found in the pasted log.")

    if not parsed.stack_addresses and not parsed.backtrace_addresses:
        report.warnings.append("No stack or backtrace addresses were detected.")

    excvaddr = parsed.registers.get("EXCVADDR")
    if excvaddr:
        try:
            excvaddr_value = int(excvaddr.address, 16)
            if excvaddr_value == 0:
                report.hints.append("EXCVADDR is 0x00000000, which strongly suggests a null-pointer access.")
            elif excvaddr_value < 0x100:
                report.hints.append("EXCVADDR is very low, which often points to a near-null pointer dereference.")
            elif excvaddr_value >= 0xFFFFFF00:
                report.hints.append("EXCVADDR is close to 0xFFFFFFFF, which often indicates invalid or uninitialized pointer data.")
        except ValueError:
            report.warnings.append(f"Could not interpret EXCVADDR value: {excvaddr.address}")

    if parsed.exception and parsed.exception.code in {28, 29}:
        report.hints.append("Load/Store prohibited exceptions usually mean invalid memory access through a bad pointer.")
    if parsed.exception and parsed.exception.code == 6:
        report.hints.append("Exception 6 indicates a divide-by-zero operation in the failing code path.")

    if gdb_path and elf_path:
        undecoded = [frame.address for frame in report.frames if frame.decoded and frame.decoded.error]
        if undecoded:
            report.warnings.append(f"Some addresses could not be resolved from the selected ELF: {', '.join(undecoded[:5])}")

    return report


def render_report(report: DecodeReport) -> str:
    parsed = report.parsed_log
    lines: list[str] = []
    resolved_elf = report.resolved_elf_path or report.request.elf_path or "not selected"
    frame_count = len(report.frames)

    lines.append("WinEspExceptionDecoder Analysis")
    lines.append("=" * 30)
    lines.append("")

    lines.append("Incident Summary")
    lines.append("-" * 16)
    if parsed.exception:
        lines.append(f"Detected issue : Exception {parsed.exception.code} ({parsed.exception.name})")
    elif parsed.panic_reason:
        lines.append(f"Detected issue : {parsed.panic_reason}")
    else:
        lines.append("Detected issue : not identified from log")
    if parsed.debug_reason:
        lines.append(f"Debug reason   : {parsed.debug_reason}")
    lines.append(f"Frames decoded : {frame_count}")
    lines.append(f"ELF source     : {resolved_elf}")
    if report.request.elf_base_path:
        lines.append(f"ELF base path  : {report.request.elf_base_path}")
    lines.append(f"GDB            : {report.request.gdb_path or 'auto-detect'}")
    lines.append("")

    lines.append("Key Registers")
    lines.append("-" * 13)
    if parsed.registers:
        for name, register in parsed.registers.items():
            decoded = report.decoded_registers.get(name)
            if decoded and decoded.symbol:
                lines.append(f"- {name:<9} 0x{register.address} -> {decoded.symbol}{_format_location(decoded)}")
            else:
                lines.append(f"- {name:<9} 0x{register.address}")
    else:
        lines.append("- No registers detected.")
    lines.append("")

    lines.append("Top Frames")
    lines.append("-" * 10)
    if report.frames:
        preview_frames = report.frames[:10]
        for index, frame in enumerate(preview_frames, start=1):
            prefix = f"{index:02d}. {frame.context:<9} 0x{frame.address}"
            if frame.decoded and frame.decoded.symbol:
                lines.append(f"{prefix}  {frame.decoded.symbol}{_format_location(frame.decoded)}")
            elif frame.decoded and frame.decoded.error:
                lines.append(f"{prefix}  unresolved ({frame.decoded.error})")
            else:
                lines.append(prefix)
        if frame_count > len(preview_frames):
            lines.append(f"... {frame_count - len(preview_frames)} more frame(s) omitted from preview")
    else:
        lines.append("No frames detected.")
    lines.append("")

    lines.append("Allocation")
    lines.append("-" * 10)
    if parsed.allocation_failure:
        line = f"Failed allocation of {parsed.allocation_failure.size} bytes at 0x{parsed.allocation_failure.address}"
        if report.decoded_allocation and report.decoded_allocation.symbol:
            line += f" -> {report.decoded_allocation.symbol}{_format_location(report.decoded_allocation)}"
        lines.append(line)
    else:
        lines.append("No failed allocation marker found.")
    lines.append("")

    lines.append("Analysis")
    lines.append("-" * 8)
    if report.hints:
        lines.extend(f"- {hint}" for hint in report.hints)
    else:
        lines.append("- No heuristic hints generated.")
    lines.append("")

    lines.append("Warnings")
    lines.append("-" * 8)
    warning_items = report.errors + report.warnings
    if warning_items:
        lines.extend(f"- {warning}" for warning in warning_items)
    else:
        lines.append("- No warnings.")

    return "\n".join(lines)


def _format_location(decoded) -> str:
    if decoded.file_path and decoded.line_number:
        return f" ({decoded.file_path}:{decoded.line_number})"
    if decoded.file_path:
        return f" ({decoded.file_path})"
    return ""
