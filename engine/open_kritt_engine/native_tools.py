"""Native (.so / ELF) analysis tools for the Android native-library specialist.

The APK's native libraries are extracted to ``unpacked/lib/<abi>/*.so`` in the workspace.
This module gives the specialist agent real, callable recon over them without a heavyweight
decompiler:

  - list_native_libs : the .so files bundled per ABI
  - native_recon     : the JNI attack surface (Java_* exports), imported functions with
                       dangerous ones flagged (system/exec/strcpy/dlopen/...), and
                       interesting embedded strings (secrets, commands, URLs, format strings)
  - native_disasm    : capstone disassembly of one function by symbol (ARM64/ARM/x86)

Every function returns a human-readable string for the agent's tool loop. Missing
libraries degrade gracefully instead of raising.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Imported symbols that indicate a real native attack surface worth investigating.
_DANGEROUS_IMPORTS = {
    # command execution
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe", "posix_spawn",
    # unsafe string / memory (classic overflow primitives)
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "memmove",
    "alloca", "stpcpy", "wcscpy",
    # dynamic loading / RWX code
    "dlopen", "dlsym", "mmap", "mprotect", "__system_property_get",
    # JNI accessors whose results are often used without bounds checks
    "GetStringUTFChars", "GetByteArrayElements", "GetPrimitiveArrayCritical", "GetStringChars",
    # weak crypto / rng
    "rand", "srand", "MD5_Init", "SHA1_Init", "DES_", "RC4",
}

_INTERESTING_STRING_MARKERS = (
    "http://", "https://", "ftp://", "ws://", "/system/", "/data/", "/sdcard/", "/bin/", "su ",
    "sh -c", "/proc/", "key", "token", "secret", "password", "passwd", "apikey", "api_key",
    "-----BEGIN", "AKIA", "firebaseio", "amazonaws", "%s", "%n", "%x", "AES", "libcrypto",
    ".so", "getprop", "magisk", "frida", "ro.debuggable", "adb",
)


def _resolve(workspace_dir: str, rel: str) -> Path | None:
    base = Path(workspace_dir).resolve()
    try:
        target = (base / str(rel).lstrip("/\\")).resolve()
    except (OSError, ValueError):
        return None
    if base not in target.parents and target != base:
        return None
    return target if target.is_file() else None


def list_native_libs(workspace_dir: str) -> str:
    lib_root = Path(workspace_dir) / "unpacked" / "lib"
    if not lib_root.is_dir():
        return "[no native libraries: unpacked/lib/ is absent — this APK bundles no .so files]"
    rows: list[str] = []
    for so in sorted(lib_root.rglob("*.so")):
        rel = so.relative_to(workspace_dir).as_posix()
        rows.append(f"{rel}  ({so.stat().st_size // 1024} KB)")
    if not rows:
        return "[no .so files under unpacked/lib/]"
    return "native libraries:\n" + "\n".join(rows[:200])


def _iter_symbols(elf):
    from elftools.elf.sections import SymbolTableSection

    seen: set[str] = set()
    for sec_name in (".dynsym", ".symtab"):
        sec = elf.get_section_by_name(sec_name)
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                name = sym.name
                if name and name not in seen:
                    seen.add(name)
                    yield sym


def native_recon(workspace_dir: str, rel: str, *, max_strings: int = 60) -> str:
    """JNI exports + imported (esp. dangerous) functions + interesting strings for one .so."""

    path = _resolve(workspace_dir, rel)
    if not path:
        return f"[error: native library not found at {rel} (use list_native_libs first)]"
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.enums import ENUM_ST_INFO_TYPE  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return f"[error: ELF parser unavailable: {exc}]"

    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            machine = elf.header["e_machine"]
            jni_exports: list[str] = []
            other_exports: list[str] = []
            imports: list[str] = []
            for sym in _iter_symbols(elf):
                info_type = sym["st_info"]["type"]
                if info_type not in ("STT_FUNC", "STT_NOTYPE"):
                    continue
                undefined = sym["st_shndx"] == "SHN_UNDEF"
                if undefined:
                    imports.append(sym.name)
                elif info_type == "STT_FUNC":
                    if sym.name.startswith(("Java_", "JNI_")):
                        jni_exports.append(sym.name)
                    else:
                        other_exports.append(sym.name)
            dangerous = sorted({i for i in imports if i in _DANGEROUS_IMPORTS})

        # Interesting strings (scan raw bytes for printable runs).
        raw = path.read_bytes()
        strings = _extract_strings(raw)
        interesting = [s for s in strings if any(m.lower() in s.lower() for m in _INTERESTING_STRING_MARKERS)]

        out = [f"ELF {path.name}  machine={machine}"]
        out.append(f"\nJNI exports ({len(jni_exports)}) — the native attack surface reachable from Java:")
        out += [f"  {n}" for n in sorted(jni_exports)[:60]] or ["  (none — no Java_* symbols; may use RegisterNatives)"]
        if dangerous:
            out.append(f"\nDANGEROUS imported functions ({len(dangerous)}):")
            out.append("  " + ", ".join(dangerous))
        out.append(f"\nother imports (sample): {', '.join(sorted(set(imports))[:40])}")
        if interesting:
            out.append(f"\ninteresting strings ({len(interesting)}):")
            out += [f"  {s[:160]}" for s in interesting[:max_strings]]
        return "\n".join(out)
    except Exception as exc:  # noqa: BLE001
        return f"[error parsing ELF {rel}: {type(exc).__name__}: {exc}]"


def _extract_strings(raw: bytes, min_len: int = 5) -> list[str]:
    out: list[str] = []
    cur: list[int] = []
    for b in raw:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", "ignore"))
            cur = []
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", "ignore"))
    # de-dup, preserve order
    seen: set[str] = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def native_disasm(workspace_dir: str, rel: str, symbol: str, *, max_insns: int = 120) -> str:
    """Disassemble one function (by symbol name) so the agent can inspect its behavior."""

    path = _resolve(workspace_dir, rel)
    if not path:
        return f"[error: native library not found at {rel}]"
    if not symbol:
        return "[error: provide a `symbol` name (e.g. a Java_* export from native_recon)]"
    try:
        from elftools.elf.elffile import ELFFile
        import capstone
    except Exception as exc:  # noqa: BLE001
        return f"[error: disassembler unavailable: {exc}]"

    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            machine = elf.header["e_machine"]
            target = None
            for sym in _iter_symbols(elf):
                if sym.name == symbol:
                    target = sym
                    break
            if target is None:
                return f"[symbol '{symbol}' not found; run native_recon to list exports]"
            addr = target["st_value"]
            size = target["st_size"] or (max_insns * 4)
            # Locate the section + file offset for this address.
            data = None
            for sec in elf.iter_sections():
                sh_addr = sec["sh_addr"]
                sh_size = sec["sh_size"]
                if sh_addr and sh_addr <= addr < sh_addr + sh_size and sec["sh_type"] == "SHT_PROGBITS":
                    off = addr - sh_addr
                    data = sec.data()[off : off + min(size, max_insns * 4)]
                    break
            if not data:
                return f"[could not locate code bytes for '{symbol}' (addr={hex(addr)})]"

        arch = {
            "EM_AARCH64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            "EM_ARM": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "EM_X86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "EM_386": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        }.get(machine)
        if not arch:
            return f"[unsupported machine for disasm: {machine}]"
        md = capstone.Cs(*arch)
        lines = [f"disasm {symbol} @ {hex(addr)} ({machine}):"]
        for i, ins in enumerate(md.disasm(data, addr)):
            if i >= max_insns:
                lines.append("  … (truncated)")
                break
            lines.append(f"  {hex(ins.address)}:  {ins.mnemonic}\t{ins.op_str}")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"[error disassembling {symbol}: {type(exc).__name__}: {exc}]"
