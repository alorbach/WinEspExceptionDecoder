from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from .models import DecodedAddress


def _search_root(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    if not root.exists():
        return []
    matches: list[Path] = []
    for pattern in patterns:
        matches.extend(root.rglob(pattern))
    return matches


def find_gdb_candidates() -> list[str]:
    candidates: list[Path] = []
    system = platform.system().lower()
    home = Path.home()

    if system == "windows":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", home))
        user_profile = Path(os.environ.get("USERPROFILE", home))
        patterns = ("xtensa-*-elf-gdb.exe", "riscv32-*-elf-gdb.exe", "xtensa-esp-elf-gdb.exe")
        roots = [
            local_app_data / "Arduino15" / "packages",
            user_profile / "AppData" / "Local" / "Arduino15" / "packages",
            Path("C:/Program Files/Arduino IDE/resources/app"),
            Path("C:/Program Files (x86)/Arduino"),
        ]
    else:
        patterns = ("xtensa-*-elf-gdb", "riscv32-*-elf-gdb", "xtensa-esp-elf-gdb")
        roots = [home / ".arduino15" / "packages", Path("/usr/local/bin"), Path("/usr/bin")]

    for root in roots:
        candidates.extend(_search_root(root, patterns))

    unique_paths: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        candidate_str = str(candidate)
        if candidate_str not in seen and candidate.is_file():
            unique_paths.append(candidate_str)
            seen.add(candidate_str)
    return unique_paths


def auto_detect_gdb() -> str | None:
    candidates = find_gdb_candidates()
    return candidates[0] if candidates else None


def find_elf_candidates(base_path: str) -> list[str]:
    root = Path(base_path)
    if not root.exists() or not root.is_dir():
        return []

    candidates = [path for path in root.rglob("*.elf") if path.is_file()]
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return [str(path) for path in candidates]


def parse_gdb_line(address: str, line: str) -> DecodedAddress:
    stripped = line.strip()
    marker = " is in "
    if marker not in stripped:
        return DecodedAddress(address=address.lower(), raw_line=stripped or None)

    symbol_part = stripped.split(marker, 1)[1]
    symbol = symbol_part
    file_path = None
    line_number = None

    if " at " in symbol_part:
        symbol, location = symbol_part.split(" at ", 1)
        if ":" in location:
            file_path, line_text = location.rsplit(":", 1)
            try:
                line_number = int(line_text)
            except ValueError:
                file_path = location
                line_number = None

    return DecodedAddress(
        address=address.lower(),
        symbol=symbol.strip(),
        file_path=file_path.strip() if file_path else None,
        line_number=line_number,
        raw_line=stripped,
    )


def decode_address(gdb_path: str, elf_path: str, address: str) -> DecodedAddress:
    if not Path(gdb_path).is_file():
        return DecodedAddress(address=address.lower(), error=f"GDB not found: {gdb_path}")
    if not Path(elf_path).is_file():
        return DecodedAddress(address=address.lower(), error=f"ELF not found: {elf_path}")

    command = [
        gdb_path,
        "--batch",
        elf_path,
        "-ex",
        "set listsize 1",
        "-ex",
        f"l *0x{address.lower()}",
        "-ex",
        "q",
    ]

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        return DecodedAddress(address=address.lower(), error=str(exc))

    output_lines = [line.strip() for line in (completed.stdout.splitlines() + completed.stderr.splitlines()) if line.strip()]
    for line in output_lines:
        if line.startswith("0x"):
            decoded = parse_gdb_line(address, line)
            if completed.returncode != 0 and not decoded.error:
                decoded.error = f"gdb exited with code {completed.returncode}"
            return decoded

    if completed.returncode != 0:
        error = f"gdb exited with code {completed.returncode}"
    elif output_lines:
        error = output_lines[-1]
    else:
        error = "No symbol information found"

    return DecodedAddress(address=address.lower(), raw_line=output_lines[-1] if output_lines else None, error=error)
