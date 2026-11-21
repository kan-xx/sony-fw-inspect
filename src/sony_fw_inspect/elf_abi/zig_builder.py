"""Reusable `zig cc` cross-compilation helper for Sony ILCE-7RM3 ARMv7 Cortex-A9 binaries.

Parameterized via `ZIG_CC` (or `shutil.which("zig")`) and `A7R3_FW_ROOT` environment variables.
Automatically applies post-link `DT_RELCOUNT = 0` normalization and gates output on `audit_arm_elf`.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Any, Sequence

from .relcount_patcher import patch_dt_relcount_zero
from .safety_auditor import audit_arm_elf

SONY_ARM_DSO_CFLAGS: tuple[str, ...] = (
    "-target",
    "arm-linux-gnueabi",
    "-mcpu=cortex_a9",
    "-marm",
    "-mfloat-abi=soft",
    "-Os",
    "-fno-builtin",
    "-fno-stack-protector",
    "-nostdlib",
    "-shared",
    "-fPIC",
    "-fvisibility=hidden",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wl,--hash-style=sysv",
    "-Wl,-z,now",
    "-Wl,-z,defs",
    "-Wl,-z,noexecstack",
)

SONY_ARM_STATIC_CFLAGS: tuple[str, ...] = (
    "-target",
    "arm-linux-musleabi",
    "-mcpu=cortex_a9",
    "-marm",
    "-Os",
    "-static",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wl,-z,noexecstack",
)


def resolve_zig_cc(explicit_zig_cc: str | None = None) -> list[str]:
    """Resolve `zig cc` invocation from explicit string, `ZIG_CC`, or `PATH`."""
    raw = explicit_zig_cc or os.environ.get("ZIG_CC")
    if raw:
        parts = shlex.split(raw)
        if not parts:
            raise RuntimeError("Empty ZIG_CC specification")
        return parts
    zig_bin = shutil.which("zig")
    if not zig_bin:
        raise RuntimeError("Could not find 'zig' on PATH; install Zig or set ZIG_CC='zig cc'")
    return [zig_bin, "cc"]


def build_sony_arm_dso(
    sources: Sequence[Path],
    output_so: Path,
    *,
    soname: str | None = None,
    link_libs: Sequence[Path] = (),
    version_script: Path | None = None,
    extra_cflags: Sequence[str] = (),
    allowed_exports: set[str] | None = None,
    allow_init: bool = False,
    allow_fini: bool = False,
    zig_cc: str | None = None,
) -> dict[str, Any]:
    """Cross-compile a Sony-compatible ARMv7 shared library, patch `DT_RELCOUNT=0`, and audit."""
    cc_cmd = resolve_zig_cc(zig_cc)
    output_so = output_so.resolve()
    output_so.parent.mkdir(parents=True, exist_ok=True)
    effective_soname = soname or output_so.name

    cmd: list[str] = [
        *cc_cmd,
        *SONY_ARM_DSO_CFLAGS,
        f"-Wl,-soname,{effective_soname}",
        *extra_cflags,
    ]
    if version_script is not None:
        cmd.append(f"-Wl,--version-script={version_script.resolve(strict=True)}")
    cmd.extend(str(Path(s).resolve(strict=True)) for s in sources)
    cmd.extend(str(Path(lib).resolve(strict=True)) for lib in link_libs)
    cmd.extend(["-o", str(output_so)])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"zig cc DSO build failed:\n{res.stderr}")

    raw_elf = output_so.read_bytes()
    patched_elf, patch_info = patch_dt_relcount_zero(raw_elf)
    output_so.write_bytes(patched_elf)

    audit = audit_arm_elf(
        patched_elf,
        allowed_exports=allowed_exports,
        allow_init=allow_init,
        allow_fini=allow_fini,
        require_gnu_stack=True,
        require_relcount_zero=True,
    )
    return {"command": cmd, "relcount_patch": patch_info, "audit": audit}


def build_sony_arm_static_elf(
    sources: Sequence[Path],
    output_elf: Path,
    *,
    extra_cflags: Sequence[str] = (),
    zig_cc: str | None = None,
) -> dict[str, Any]:
    """Cross-compile a static musl ARMv7 helper ELF (`commit.elf` / `boot-guard.elf` / observers)."""
    cc_cmd = resolve_zig_cc(zig_cc)
    output_elf = output_elf.resolve()
    output_elf.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        *cc_cmd,
        *SONY_ARM_STATIC_CFLAGS,
        *extra_cflags,
        *(str(Path(s).resolve(strict=True)) for s in sources),
        "-o",
        str(output_elf),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"zig cc static ELF build failed:\n{res.stderr}")

    audit = audit_arm_elf(
        output_elf.read_bytes(),
        allow_init=True,
        allow_fini=True,
        require_gnu_stack=False,
        require_relcount_zero=False,
    )
    return {"command": cmd, "audit": audit}
