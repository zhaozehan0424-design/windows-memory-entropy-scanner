#!/usr/bin/env python3
"""
Scan a Windows process for entropy-rich 32-byte values stored as 64 ASCII
hexadecimal characters in committed writable virtual memory regions.

The scanner uses ctypes bindings to the Windows APIs requested by the caller:
OpenProcess, VirtualQueryEx, and ReadProcessMemory. Process-name lookup is also
implemented with Toolhelp32 APIs through ctypes so the script has no third-party
runtime dependencies.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import math
import os
import re
import sys
from typing import Iterable, Iterator


if os.name != "nt":
    raise SystemExit("mem_scanner.py supports Windows only.")


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300

HEX_BYTE_RE = re.compile(rb"^[0-9A-Fa-f]{64}$")
HEX64_STRICT_RE = re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")
HEX64_EMBEDDED_RE = re.compile(rb"([0-9A-Fa-f]{64})")


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.GetNativeSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
kernel32.GetNativeSystemInfo.restype = None

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.POINTER(LUID),
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str | None = None


@dataclass(frozen=True)
class RegionInfo:
    base: int
    size: int
    state: int
    protect: int


@dataclass(frozen=True)
class HexBlockMatch:
    address: int
    region_base: int
    protect: int
    entropy: float
    distinct_bytes: int
    hex_text: str


@dataclass
class ScanStats:
    regions_seen: int = 0
    regions_scanned: int = 0
    bytes_read: int = 0
    read_failures: int = 0
    pages_skipped: int = 0
    matches: int = 0


def win_error(prefix: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{prefix}: {ctypes.FormatError(code).strip()}")


def ptr_to_int(value: object) -> int:
    if value is None:
        return 0
    return int(value)


def get_system_info() -> SYSTEM_INFO:
    info = SYSTEM_INFO()
    kernel32.GetNativeSystemInfo(ctypes.byref(info))
    return info


def enable_debug_privilege() -> tuple[bool, str]:
    token = wintypes.HANDLE()
    current_process = kernel32.GetCurrentProcess()
    if not advapi32.OpenProcessToken(
        current_process,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False, str(win_error("OpenProcessToken failed"))

    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False, str(win_error("LookupPrivilegeValueW failed"))

        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(privileges),
            0,
            None,
            None,
        ):
            return False, str(win_error("AdjustTokenPrivileges failed"))

        error = ctypes.get_last_error()
        if error == ERROR_NOT_ALL_ASSIGNED:
            return False, "SeDebugPrivilege is not assigned to this token"
        if error:
            return False, f"AdjustTokenPrivileges returned WinError {error}"
        return True, "enabled"
    finally:
        kernel32.CloseHandle(token)


def enumerate_processes() -> list[ProcessInfo]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if ptr_to_int(snapshot) == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot failed")

    processes: list[ProcessInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise win_error("Process32FirstW failed")

        while True:
            processes.append(ProcessInfo(int(entry.th32ProcessID), entry.szExeFile))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return processes


def resolve_process_selector(selector: str) -> list[ProcessInfo]:
    if selector.isdecimal():
        return [ProcessInfo(int(selector), None)]

    wanted = selector.casefold()
    wanted_exe = wanted if wanted.endswith(".exe") else f"{wanted}.exe"
    matches = [
        proc
        for proc in enumerate_processes()
        if proc.name and proc.name.casefold() in {wanted, wanted_exe}
    ]
    if matches:
        return matches

    raise SystemExit(f"No running process matched name {selector!r}. Use a PID for an exact target.")


def open_process(pid: int) -> wintypes.HANDLE:
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise win_error(f"OpenProcess failed for PID {pid}")
    return handle


def is_scan_candidate_region(mbi: MEMORY_BASIC_INFORMATION) -> bool:
    if int(mbi.State) != MEM_COMMIT:
        return False
    protect = int(mbi.Protect)
    if protect & PAGE_GUARD or protect & PAGE_NOACCESS:
        return False
    base_protect = protect & 0xFF
    return base_protect in {PAGE_READWRITE, PAGE_EXECUTE_READWRITE}


def protect_name(protect: int) -> str:
    base_protect = protect & 0xFF
    names = {
        PAGE_READWRITE: "PAGE_READWRITE",
        PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
    }
    modifiers: list[str] = []
    if protect & PAGE_GUARD:
        modifiers.append("GUARD")
    label = names.get(base_protect, f"0x{base_protect:X}")
    if modifiers:
        label = f"{label}|{'|'.join(modifiers)}"
    return label


def iter_virtual_regions(handle: wintypes.HANDLE) -> Iterator[RegionInfo]:
    sysinfo = get_system_info()
    page_size = int(sysinfo.dwPageSize) or 0x1000
    address = ptr_to_int(sysinfo.lpMinimumApplicationAddress)
    max_address = ptr_to_int(sysinfo.lpMaximumApplicationAddress)
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while address < max_address:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
        if not result:
            error = ctypes.get_last_error()
            if error == 87:  # ERROR_INVALID_PARAMETER, normally past the address space.
                break
            address += page_size
            continue

        base = ptr_to_int(mbi.BaseAddress)
        size = int(mbi.RegionSize)
        if size <= 0:
            address += page_size
            continue

        yield RegionInfo(base=base, size=size, state=int(mbi.State), protect=int(mbi.Protect))

        next_address = base + size
        if next_address <= address:
            address += page_size
        else:
            address = next_address


def read_process_memory(handle: wintypes.HANDLE, address: int, size: int) -> bytes | None:
    if size <= 0:
        return b""
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok:
        return None
    if bytes_read.value == 0:
        return b""
    return bytes(buffer[: bytes_read.value])


def iter_readable_chunks(
    handle: wintypes.HANDLE,
    region: RegionInfo,
    chunk_size: int,
    page_size: int,
    stats: ScanStats,
) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset < region.size:
        wanted = min(chunk_size, region.size - offset)
        address = region.base + offset
        data = read_process_memory(handle, address, wanted)
        if data is not None:
            stats.bytes_read += len(data)
            if data:
                yield address, data
            offset += max(len(data), wanted)
            continue

        stats.read_failures += 1
        fallback_end = offset + wanted
        page_offset = offset
        while page_offset < fallback_end:
            page_wanted = min(page_size, fallback_end - page_offset)
            page_address = region.base + page_offset
            page = read_process_memory(handle, page_address, page_wanted)
            if page:
                stats.bytes_read += len(page)
                yield page_address, page
            else:
                stats.pages_skipped += 1
            page_offset += page_wanted
        offset = fallback_end


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def analyze_hex_32byte_block(
    candidate: bytes,
    min_entropy: float,
    min_distinct: int,
) -> tuple[bool, float, int]:
    if not HEX_BYTE_RE.fullmatch(candidate):
        return False, 0.0, 0

    raw = bytes.fromhex(candidate.decode("ascii"))
    if len(raw) != 32:
        return False, 0.0, 0
    if not any(raw):
        return False, 0.0, 0

    distinct = len(set(raw))
    entropy = shannon_entropy(raw)
    return entropy >= min_entropy and distinct >= min_distinct, entropy, distinct


def find_entropy_rich_hex_blocks(
    data: bytes,
    base_address: int,
    region: RegionInfo,
    min_entropy: float,
    min_distinct: int,
    strict_boundaries: bool,
) -> Iterator[HexBlockMatch]:
    pattern = HEX64_STRICT_RE if strict_boundaries else HEX64_EMBEDDED_RE
    for match in pattern.finditer(data):
        candidate = match.group(1)
        ok, entropy, distinct = analyze_hex_32byte_block(candidate, min_entropy, min_distinct)
        if not ok:
            continue
        yield HexBlockMatch(
            address=base_address + match.start(1),
            region_base=region.base,
            protect=region.protect,
            entropy=entropy,
            distinct_bytes=distinct,
            hex_text=candidate.decode("ascii").upper(),
        )


def scan_process(
    handle: wintypes.HANDLE,
    chunk_size: int,
    min_entropy: float,
    min_distinct: int,
    strict_boundaries: bool,
    stats: ScanStats,
) -> Iterator[HexBlockMatch]:
    sysinfo = get_system_info()
    page_size = int(sysinfo.dwPageSize) or 0x1000
    overlap = 64

    for region in iter_virtual_regions(handle):
        stats.regions_seen += 1
        if region.state != MEM_COMMIT:
            continue
        mbi_like = MEMORY_BASIC_INFORMATION()
        mbi_like.State = region.state
        mbi_like.Protect = region.protect
        if not is_scan_candidate_region(mbi_like):
            continue

        stats.regions_scanned += 1
        previous_tail = b""
        previous_end: int | None = None
        reported_addresses: set[int] = set()

        for chunk_base, chunk in iter_readable_chunks(handle, region, chunk_size, page_size, stats):
            if previous_end != chunk_base:
                previous_tail = b""

            combined_base = chunk_base - len(previous_tail)
            combined = previous_tail + chunk
            for match in find_entropy_rich_hex_blocks(
                combined,
                combined_base,
                region,
                min_entropy,
                min_distinct,
                strict_boundaries,
            ):
                if match.address in reported_addresses:
                    continue
                reported_addresses.add(match.address)
                stats.matches += 1
                yield match

            previous_tail = combined[-overlap:]
            previous_end = chunk_base + len(chunk)


def parse_chunk_size(value: str) -> int:
    text = value.strip().lower()
    multiplier = 1
    for suffix, factor in (("kb", 1024), ("k", 1024), ("mb", 1024 * 1024), ("m", 1024 * 1024)):
        if text.endswith(suffix):
            multiplier = factor
            text = text[: -len(suffix)]
            break
    try:
        size = int(text) * multiplier
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid chunk size: {value!r}") from exc
    if size < 4096:
        raise argparse.ArgumentTypeError("chunk size must be at least 4096 bytes")
    return size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan committed PAGE_READWRITE/PAGE_EXECUTE_READWRITE memory for "
            "entropy-rich 32-byte values represented as 64 ASCII hex characters."
        )
    )
    parser.add_argument("target", help="PID or exact process name, e.g. 1234 or prototype.exe")
    parser.add_argument(
        "--chunk-size",
        type=parse_chunk_size,
        default=8 * 1024 * 1024,
        help="Read size per ReadProcessMemory call; accepts bytes, K/KiB-style, or M/MB (default: 8M).",
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=4.0,
        help="Minimum Shannon entropy over the decoded 32-byte value (default: 4.0; max for 32 bytes is 5.0).",
    )
    parser.add_argument(
        "--min-distinct",
        type=int,
        default=16,
        help="Minimum number of distinct decoded byte values in the 32-byte block (default: 16).",
    )
    parser.add_argument(
        "--embedded",
        action="store_true",
        help="Also consider 64-character hex windows embedded inside longer hex runs.",
    )
    parser.add_argument(
        "--max-matches",
        type=int,
        default=0,
        help="Stop after this many matches; 0 means unlimited (default: 0).",
    )
    parser.add_argument(
        "--no-debug-privilege",
        action="store_true",
        help="Do not attempt to enable SeDebugPrivilege before opening the target process.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress privilege and target banners; matched blocks and summary still print.",
    )
    return parser


def print_match(match: HexBlockMatch) -> None:
    print(
        f"0x{match.address:016X}  "
        f"region=0x{match.region_base:016X}  "
        f"{protect_name(match.protect):<22}  "
        f"entropy={match.entropy:0.2f}  "
        f"distinct={match.distinct_bytes:02d}  "
        f"{match.hex_text}"
    )


def scan_one_process(proc: ProcessInfo, args: argparse.Namespace) -> int:
    handle = open_process(proc.pid)
    stats = ScanStats()
    limit_reached = False
    printed = 0

    try:
        if not args.quiet:
            label = f"{proc.name} " if proc.name else ""
            print(f"\nScanning PID {proc.pid} {label}".rstrip())
            print("Address             Region              Protection              Entropy  Distinct  Hex")

        for match in scan_process(
            handle,
            args.chunk_size,
            args.min_entropy,
            args.min_distinct,
            not args.embedded,
            stats,
        ):
            print_match(match)
            printed += 1
            if args.max_matches and printed >= args.max_matches:
                limit_reached = True
                break
    finally:
        kernel32.CloseHandle(handle)

    if limit_reached:
        print(f"Match limit reached for PID {proc.pid}; use --max-matches 0 for no limit.")

    print(
        f"Summary PID {proc.pid}: "
        f"matches={stats.matches}, "
        f"regions_scanned={stats.regions_scanned}/{stats.regions_seen}, "
        f"bytes_read={stats.bytes_read}, "
        f"read_failures={stats.read_failures}, "
        f"pages_skipped={stats.pages_skipped}"
    )
    return stats.matches


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.min_entropy < 0 or args.min_entropy > 5.0:
        parser.error("--min-entropy must be between 0.0 and 5.0 for a 32-byte sample")
    if args.min_distinct < 1 or args.min_distinct > 32:
        parser.error("--min-distinct must be between 1 and 32")
    if args.max_matches < 0:
        parser.error("--max-matches cannot be negative")

    if not args.no_debug_privilege:
        ok, message = enable_debug_privilege()
        if not args.quiet:
            status = "enabled" if ok else f"not enabled ({message})"
            print(f"SeDebugPrivilege: {status}")

    processes = resolve_process_selector(args.target)
    if not args.quiet and len(processes) > 1:
        pids = ", ".join(str(proc.pid) for proc in processes)
        print(f"Process name matched {len(processes)} processes; scanning PIDs: {pids}")

    total_matches = 0
    failures = 0
    for proc in processes:
        try:
            total_matches += scan_one_process(proc, args)
        except OSError as exc:
            failures += 1
            print(f"PID {proc.pid}: {exc}", file=sys.stderr)

    return 2 if failures and not total_matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
