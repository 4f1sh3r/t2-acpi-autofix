#!/usr/bin/env python3
"""Detect, patch, validate, and deploy T2 Mac ACPI fixes on Linux.

Building and validating the patched tables works identically on any distro:
that part only ever touches files under /sys/firmware/acpi/tables and a
private working directory. Deployment -- getting the patched tables into an
initramfs so the kernel loads them at boot -- is the one part that is
genuinely distro-specific, so it is driven by whichever tool is actually
installed rather than by guessing from distro name:
  * dracut present -> the existing dracut.conf.d/acpi_override mechanism
    (Fedora's default; also covers Arch/Manjaro/EndeavourOS if dracut was
    installed in place of mkinitcpio).
  * update-initramfs present (and no dracut) -> an initramfs-tools hook
    (Debian/Ubuntu's default).
  * mkinitcpio present (and neither of the above) -> a custom mkinitcpio
    install hook (Arch/Manjaro/EndeavourOS's default).
  * anything else (NixOS, Gentoo with genkernel/booster, or no recognized
    tool at all) -> the tables are still built and validated, but this
    script does not attempt an automated deploy: NixOS's initrd is built
    declaratively from configuration.nix, so writing files under /etc
    would just be discarded on the next rebuild, and Gentoo's initramfs
    tooling is too heterogeneous to guess safely. Manual next steps are
    printed instead.
Only the dracut path has been verified against a real deployment; the
others follow each tool's documented hook mechanism but have not been
exercised on real hardware -- treat their success as "should work", not
"confirmed", until someone reports back.

The script uses only ACPI tables from the running machine. CpuSSDT follows
the repository's disassemble/edit-ASL/recompile procedure: the table is
disassembled with iasl, the relevant ASL source is rewritten with a
structurally-verified text transform, and the result is recompiled with
iasl -- iasl's own compiler is the final judge of correctness. CpuSSDT SDTL
bits are derived from the running machine instead of assuming a fixed
bitmask.

The DSDT is handled differently: rather than a full disassemble/edit/
recompile round trip, the documented _OSC methods are located and replaced
directly in the AML bytes with a length-preserving structural patch. This is
deliberate -- real-world Apple DSDTs routinely contain unrelated constructs
(legacy VarPackage brightness tables, forward references, duplicate
namespace objects) that iasl's decompiler cannot faithfully round-trip back
through its own compiler, so requiring the *entire* multi-thousand-line
DSDT to recompile cleanly rejects perfectly patchable machines for reasons
that have nothing to do with the _OSC fix itself. Operating on the AML
bytes directly means the rest of the table never has to survive a
recompile.

Real T2 firmware implements the buggy _OSC in two different AML shapes, and
this script recognizes both (see find_osc_replacements()):
  * "Family A" -- two separate _OSC methods, each guarding an inline
    Buffer(ToUUID(...)) comparison. Seen on e.g. MacBookAir9,1 and
    MacBookPro16,2.
  * "Family B" -- a single \\_SB._OSC implementing Apple's PCI-hotplug
    negotiation (NHPG/NPME/OSDW/OSCC), where the UUID comparison references
    a pre-declared named Buffer(ToUUID(...)) object instead of an inline
    literal. Confirmed byte-identical across MacBookPro15,1, MacBookPro16,1
    and Macmini8,1 firmware. This shape only ever implements the PCI Host
    Bridge UUID; the platform-capabilities UUID simply has no method on
    these models, which is normal, not an error.
A model may resolve one or both of the two documented UUIDs; the script
proceeds as long as at least one resolves, and logs (without failing) any
UUID that has no matching method at all on the running machine.

Because the DSDT patch bypasses iasl's compiler, it is independently
re-checked with iasl's *decompiler* (`iasl -d`, never `-tc`): the patched
table's disassembly is compared against a disassembly of the machine's own
unmodified DSDT, and both are checked against the documented AML shape.
Disassembly alone tolerates the forward references and duplicate namespace
objects that the compiler rejects, but it is still an independent second
parser of the AML this script hand-built -- not a replacement for the
byte-level structural checks done while building the patch, a second,
differently-implemented opinion on the same bytes. If a DSDT's _OSC methods
don't match either documented broken shape byte-for-byte, the script
refuses to build an override for it rather than guessing, and the manual
README steps remain available.

Default behavior:
  * inspect the current boot's kernel log (journal, or dmesg where there is
    no systemd journal) for both documented problems;
  * patch only the affected table(s);
  * require CpuSSDT to compile with 0 Errors/Warnings;
  * derive the CpuSSDT SDTL mask from sub-tables already present in the XSDT;
  * replace each resolved DSDT _OSC method's AML bytes in place to match the
    documented fix, preserving table size and all enclosing package lengths;
  * independently re-verify the patched DSDT via iasl disassembly (no
    recompile) before trusting the binary patch;
  * increment the OEM revision and recompute the checksum on both tables;
  * deploy via /usr/local/lib/firmware/acpi and whichever initramfs tool is
    installed (dracut, initramfs-tools, or mkinitcpio), or print manual
    instructions if none is recognized;
  * do not reboot unless --reboot is supplied.
"""

from __future__ import annotations

__author__ = "Alexander Fischer <alexander@fischermail.me>"

import argparse
from collections import Counter
import datetime as dt
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import uuid as uuidlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

ACPI_TABLE_DIR = Path("/sys/firmware/acpi/tables")
DEPLOY_DIR = Path("/usr/local/lib/firmware/acpi")
DRACUT_CONF = Path("/etc/dracut.conf.d/acpi-cpussdt-fix.conf")
INITRAMFS_TOOLS_HOOK = Path("/etc/initramfs-tools/hooks/zzz-acpi-t2-fix")
MKINITCPIO_HOOK_INSTALL = Path("/etc/initcpio/install/acpi_t2_fix")
MKINITCPIO_CONF = Path("/etc/mkinitcpio.conf")
BACKUP_ROOT = Path("/var/backups/acpi-t2-fix")

CPU_JOURNAL_GREP = "Marking method"
DSDT_JOURNAL_GREP = "AE_AML_BUFFER_LIMIT"
CPU_EXPECTED_RE = re.compile(
    r"Marking\s+method\s+.*?_PDC\s+as\s+Serialized.*AE_ALREADY_EXISTS", re.I
)

UUID_SB_OSC = "0811b06e-4a27-44f9-8d60-3cbbc22e7b48"  # ACPI "Platform-wide Capabilities"
UUID_PCI0_OSC = "33db4d5b-1ff7-401c-9657-7441c03dd766"  # ACPI "PCI Host Bridge Device"

DRACUT_REQUIRED_LINES = (
    'acpi_override="yes"',
    'acpi_table_dir="/usr/local/lib/firmware/acpi"',
)

# Deploy strategy -> the command required to be installed for that strategy.
DEPLOY_STRATEGY_COMMAND = {
    "dracut": "dracut",
    "initramfs-tools": "update-initramfs",
    "mkinitcpio": "mkinitcpio",
}


VERBOSE = False  # set from --debug in main(); gates command echo and iasl stdout


class FixError(RuntimeError):
    """Expected, user-facing failure."""


@dataclass(frozen=True)
class Detection:
    cpussdt_problem: bool
    dsdt_problem: bool
    cpussdt_log: str
    dsdt_log: str


@dataclass(frozen=True)
class BuiltTable:
    kind: str
    source_table: Path
    details: Path
    aml: Path
    deploy_name: str


@dataclass(frozen=True)
class CompileResult:
    aml: Path
    errors: int
    warnings: int
    warning_codes: Counter[str]


@dataclass(frozen=True)
class AmlMethod:
    start: int
    pkg_length: int
    pkg_length_size: int
    flags: int
    body_start: int
    end: int

    @property
    def body_length(self) -> int:
        return self.end - self.body_start


# ---------------------------------------------------------------------------
# Small helpers: logging, subprocess execution
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    print(f"[acpi-fix] {message}", flush=True)


def run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    echo_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    if VERBOSE:
        log("$ " + " ".join(str(x) for x in argv))
    proc = subprocess.run(
        list(argv),
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if echo_output and VERBOSE and proc.stdout:
        print(proc.stdout.rstrip())
    if check and proc.returncode != 0:
        output = proc.stdout.strip()
        detail = f"\n{output}" if output else ""
        raise FixError(
            f"Command failed with exit status {proc.returncode}: "
            f"{' '.join(argv)}{detail}"
        )
    return proc


# ---------------------------------------------------------------------------
# Preconditions: root, Apple/Intel hardware, required tools
# ---------------------------------------------------------------------------


def require_root() -> None:
    if os.geteuid() != 0:
        raise FixError("Run this script as root, for example: sudo ./t2_acpi_fix.py")


def read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.is_file():
        raise FixError("/etc/os-release is missing; cannot identify the distro.")
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"').strip("'")
    return result


# Package name for acpica-tools (provides iasl), keyed by /etc/os-release ID.
# Falls back to ID_LIKE, then to a generic hint if the distro isn't recognized.
IASL_INSTALL_HINTS: dict[str, str] = {
    "fedora": "sudo dnf install acpica-tools",
    "arch": "sudo pacman -S acpica",
    "manjaro": "sudo pacman -S acpica",
    "endeavouros": "sudo pacman -S acpica",
    "debian": "sudo apt install acpica-tools",
    "ubuntu": "sudo apt install acpica-tools",
    "nixos": "nix-shell -p acpica-tools  (or add pkgs.acpica-tools to environment.systemPackages)",
    "gentoo": "sudo emerge --ask sys-power/acpica",
}


def iasl_install_hint(os_release: dict[str, str]) -> str:
    distro_id = os_release.get("ID", "").lower()
    if distro_id in IASL_INSTALL_HINTS:
        return IASL_INSTALL_HINTS[distro_id]
    for like in os_release.get("ID_LIKE", "").lower().split():
        if like in IASL_INSTALL_HINTS:
            return IASL_INSTALL_HINTS[like]
    return "install the 'acpica' / 'acpica-tools' package for your distro"


def require_apple_intel_supported() -> tuple[str, dict[str, str]]:
    os_release = read_os_release()

    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise FixError(
            f"The documented fix is for Intel T2 Macs; detected architecture "
            f"{platform.machine()!r}."
        )

    vendor_path = Path("/sys/class/dmi/id/sys_vendor")
    product_path = Path("/sys/class/dmi/id/product_name")
    vendor = vendor_path.read_text(errors="replace").strip() if vendor_path.exists() else ""
    product = product_path.read_text(errors="replace").strip() if product_path.exists() else ""

    if "apple" not in vendor.lower():
        raise FixError(
            f"This does not appear to be Apple hardware; DMI sys_vendor={vendor!r}."
        )
    if not ACPI_TABLE_DIR.is_dir():
        raise FixError(f"ACPI table directory is unavailable: {ACPI_TABLE_DIR}")

    return product or "AppleMac", os_release


def require_commands(commands: Iterable[str], os_release: dict[str, str]) -> None:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        hint = ""
        if "iasl" in missing:
            hint = f" Install it with: {iasl_install_hint(os_release)}"
        raise FixError(f"Missing required command(s): {', '.join(missing)}.{hint}")


def detect_deploy_strategy(os_release: dict[str, str]) -> str:
    """Pick how to get built tables into an initramfs, by tool presence, not
    by distro name -- see the module docstring for why. Returns one of
    "dracut", "initramfs-tools", "mkinitcpio", or "manual".

    NixOS is special-cased to "manual" even if some of these binaries happen
    to be present: NixOS's initrd is rebuilt from configuration.nix, so
    writing files under /etc here would just be discarded on the next
    `nixos-rebuild switch`.
    """
    if os_release.get("ID", "").lower() == "nixos":
        return "manual"
    for strategy, command in DEPLOY_STRATEGY_COMMAND.items():
        if shutil.which(command) is not None:
            return strategy
    return "manual"


def reboot_command() -> list[str]:
    return ["systemctl", "reboot"] if has_systemd_journal() else ["reboot"]


# ---------------------------------------------------------------------------
# Detecting which of the two documented bugs affects this boot
# ---------------------------------------------------------------------------


def has_systemd_journal() -> bool:
    return Path("/run/systemd/system").is_dir() and shutil.which("journalctl") is not None


def kernel_log_grep(pattern: str) -> str:
    """Search the current boot's kernel log for `pattern`.

    Prefers the systemd journal (matches exactly this boot); falls back to
    `dmesg` on machines without systemd-journald (e.g. Gentoo/OpenRC), which
    only has the current boot's ring buffer anyway.
    """
    if has_systemd_journal():
        proc = run(
            ["journalctl", "-b", "0", "-k", "--no-pager", f"--grep={pattern}"],
            check=False,
        )
        # journalctl returns 1 when no entries match.
        if proc.returncode not in (0, 1):
            raise FixError(
                f"journalctl failed while searching for {pattern!r}:\n{proc.stdout.strip()}"
            )
        return proc.stdout

    require_commands(("dmesg",), {})
    proc = run(["dmesg", "--kernel"], check=False)
    if proc.returncode != 0:
        raise FixError(f"dmesg failed while searching for {pattern!r}:\n{proc.stdout.strip()}")
    return "\n".join(line for line in proc.stdout.splitlines() if pattern in line)


def detect_problems() -> Detection:
    cpu_log = kernel_log_grep(CPU_JOURNAL_GREP)
    dsdt_log = kernel_log_grep(DSDT_JOURNAL_GREP)

    cpussdt_problem = bool(CPU_EXPECTED_RE.search(cpu_log))

    normalized = dsdt_log.replace("\\", "")
    has_buffer_error = "AE_AML_BUFFER_LIMIT" in normalized
    has_documented_osc = any(
        marker in normalized
        for marker in ("_SB._OSC", "_SB.PCI0._OSC", "Index (0x00000008)")
    )
    dsdt_problem = has_buffer_error and has_documented_osc

    return Detection(cpussdt_problem, dsdt_problem, cpu_log, dsdt_log)


def safe_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def make_workdir(requested: str | None, timestamp: str) -> Path:
    # A fresh, timestamped, exist_ok=False directory: two concurrent runs (or
    # a re-run after a crash) can never silently mix their intermediate files.
    path = Path(requested).resolve() if requested else Path(f"/var/tmp/acpi-t2-fix-{timestamp}")
    try:
        path.mkdir(parents=True, exist_ok=False)
        path.chmod(0o700)
    except OSError as exc:
        raise FixError(f"Cannot create new working directory {path}: {exc}") from exc
    return path


# ---------------------------------------------------------------------------
# CpuSSDT fix (the SMPBOOT/resume-time bug): disassemble -> rewrite the ASL
# source text -> recompile with iasl. Safe to recompile the whole table here
# because CpuSSDT is small and, unlike the DSDT, has no history of failing to
# round-trip through iasl on real hardware.
# ---------------------------------------------------------------------------


def find_cpussdt_table() -> Path:
    matches: list[Path] = []
    for candidate in sorted(ACPI_TABLE_DIR.glob("SSDT*")):
        if not candidate.is_file():
            continue
        try:
            data = candidate.read_bytes()
        except OSError as exc:
            raise FixError(f"Cannot read ACPI table {candidate}: {exc}") from exc
        if len(data) < 36 or data[:4] != b"SSDT":
            continue
        table_id = data[16:24].decode("ascii", errors="replace")
        if normalize_table_id(table_id) == "CPUSSDT":
            matches.append(candidate)

    if not matches:
        raise FixError(
            f"No SSDT with OEM Table ID 'CpuSsdt' was found under {ACPI_TABLE_DIR}."
        )
    if len(matches) > 1:
        joined = ", ".join(str(path) for path in matches)
        raise FixError(f"Multiple CpuSsdt candidates were found; refusing ambiguity: {joined}")
    return matches[0]


def copy_and_disassemble(
    source: Path,
    workdir: Path,
    *,
    external_tables: Sequence[Path] = (),
) -> tuple[Path, Path]:
    local_source = workdir / source.name
    shutil.copy2(source, local_source)
    argv = ["iasl"]
    if external_tables:
        argv.extend(["-e", *(table.name for table in external_tables)])
    argv.extend(["-d", local_source.name])
    run(argv, cwd=workdir, echo_output=True)
    dsl = local_source.with_suffix(".dsl")
    if not dsl.is_file():
        raise FixError(f"iasl did not create expected DSL file: {dsl}")
    return local_source, dsl


def increment_definition_revision(text: str, signature: str, table_id: str | None) -> str:
    table_id_pattern = re.escape(table_id) if table_id is not None else r'[^"\r\n]*'
    pattern = re.compile(
        rf'^(?P<prefix>\s*DefinitionBlock\s*\(\s*""\s*,\s*"{re.escape(signature)}"'
        rf'\s*,\s*\d+\s*,\s*"[^"\r\n]*"\s*,\s*"{table_id_pattern}"\s*,\s*)'
        rf'(?P<revision>0x[0-9A-Fa-f]+|\d+)(?P<suffix>\s*\).*)$',
        re.MULTILINE,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        wanted = f"{signature}/{table_id or '*'}"
        raise FixError(
            f"Expected exactly one DefinitionBlock for {wanted}, found {len(matches)}."
        )

    match = matches[0]
    old_token = match.group("revision")
    old_value = int(old_token, 0)
    if old_value >= 0xFFFFFFFF:
        raise FixError("OEM revision cannot be incremented beyond 0xFFFFFFFF.")
    new_token = f"0x{old_value + 1:08X}"
    return text[: match.start()] + match.group("prefix") + new_token + match.group("suffix") + text[match.end() :]


def normalize_table_id(value: str) -> str:
    return re.sub(r"[\x00\s]+", "", value).upper()


def loaded_ssdt_table_ids() -> dict[str, list[str]]:
    """Return normalized OEM Table IDs for SSDTs already loaded by the kernel."""
    result: dict[str, list[str]] = {}
    for candidate in sorted(ACPI_TABLE_DIR.glob("SSDT*")):
        if not candidate.is_file():
            continue
        try:
            data = candidate.read_bytes()
        except OSError as exc:
            raise FixError(f"Cannot read ACPI table {candidate}: {exc}") from exc
        if len(data) < 36 or data[:4] != b"SSDT":
            continue
        declared_length = struct.unpack_from("<I", data, 4)[0]
        if declared_length != len(data):
            raise FixError(
                f"Loaded SSDT {candidate} has header length {declared_length}, "
                f"but file size {len(data)}."
            )
        raw_id = data[16:24].decode("ascii", errors="replace").rstrip("\x00 ")
        normalized = normalize_table_id(raw_id)
        if normalized:
            result.setdefault(normalized, []).append(candidate.name)
    return result


def asl_integer(token: str) -> int:
    value = token.strip()
    named = {"ZERO": 0, "ONE": 1, "ONES": 0xFFFFFFFFFFFFFFFF}
    if value.upper() in named:
        return named[value.upper()]
    try:
        return int(value, 0)
    except ValueError as exc:
        raise FixError(f"Unsupported ASL integer token: {token!r}") from exc


def strip_asl_comments(text: str) -> str:
    # Shared with the DSDT independent-validation code further below: both
    # CpuSSDT's text patching and the DSDT's post-patch disassembly checks
    # need to search decompiled ASL without matching inside comments.
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*", " ", text)


def find_matching_brace(text: str, opening: int) -> int:
    depth = 0
    in_string = False
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise FixError("Could not find the end of the CpuSSDT package block.")


def cpussdt_package_elements(text: str) -> list[str | int]:
    clean = strip_asl_comments(text)
    match = re.search(
        r"\bName\s*\(\s*(?:\\)?SSDT\s*,\s*Package\s*\([^)]*\)\s*\{",
        clean,
        re.IGNORECASE,
    )
    if not match:
        raise FixError("CpuSsdt does not contain the expected SSDT Package object.")
    opening = clean.find("{", match.start())
    closing = find_matching_brace(clean, opening)
    body = clean[opening + 1 : closing]
    token_re = re.compile(
        r'"(?P<string>[^"\\]*(?:\\.[^"\\]*)*)"|'
        r'(?<![A-Za-z0-9_])(?P<number>Zero|One|Ones|0x[0-9A-Fa-f]+|\d+)(?![A-Za-z0-9_])',
        re.IGNORECASE,
    )
    elements: list[str | int] = []
    for token in token_re.finditer(body):
        if token.group("string") is not None:
            elements.append(token.group("string"))
        else:
            elements.append(asl_integer(token.group("number")))
    if not elements:
        raise FixError("The CpuSSDT SSDT package could not be parsed.")
    return elements


def derive_cpussdt_sdtl_mask(
    text: str,
    loaded_ids: dict[str, list[str]],
) -> tuple[int, list[tuple[str, int, str, str]]]:
    """Derive bits for sub-tables that Linux has already loaded from the XSDT.

    Each dynamic Load() in CpuSsdt is associated with a package entry and an
    SDTL bit. We set a bit only when a currently loaded SSDT has the same OEM
    Table ID. This avoids hard-coding 0x3A and also avoids suppressing loads for
    HWP/PSD tables that are not static on a particular model.
    """
    elements = cpussdt_package_elements(text)
    clean = strip_asl_comments(text)
    integer_token = r"(?:Zero|One|Ones|0x[0-9A-Fa-f]+|\d+)"
    op_region_re = re.compile(
        rf"\bOperationRegion\s*\(\s*(?P<region>[A-Za-z_][A-Za-z0-9_]{{0,3}})\s*,"
        rf"\s*SystemMemory\s*,\s*DerefOf\s*\(\s*(?:\\)?SSDT\s*\[\s*"
        rf"(?P<index>{integer_token})\s*\]",
        re.IGNORECASE,
    )
    mask_assign_re = re.compile(
        rf"(?:\\)?SDTL\s*\|=\s*(?P<mask>{integer_token})",
        re.IGNORECASE,
    )
    mask_test_re = re.compile(
        rf"(?:\\)?SDTL\s*&\s*(?P<mask>{integer_token})",
        re.IGNORECASE,
    )

    mappings: list[tuple[str, int, str, str]] = []
    seen_labels: set[str] = set()
    for operation in op_region_re.finditer(clean):
        region = operation.group("region")
        after = clean[operation.end() : operation.end() + 600]
        if not re.search(rf"\bLoad\s*\(\s*{re.escape(region)}\s*,", after, re.IGNORECASE):
            continue

        element_index = asl_integer(operation.group("index"))
        if element_index <= 0 or element_index >= len(elements):
            raise FixError(
                f"CpuSsdt OperationRegion {region} references package index "
                f"{element_index}, outside the parsed SSDT package."
            )
        label_value = elements[element_index - 1]
        address_value = elements[element_index]
        if not isinstance(label_value, str) or not isinstance(address_value, int):
            raise FixError(
                f"CpuSsdt package index {element_index} for region {region} does not "
                "follow the expected label/address layout."
            )
        label = normalize_table_id(label_value)
        if not label or label not in loaded_ids:
            continue

        before = clean[max(0, operation.start() - 1200) : operation.start()]
        assignments = list(mask_assign_re.finditer(before))
        if not assignments:
            raise FixError(
                f"Could not find an SDTL bit assignment for loaded sub-table {label} "
                f"near OperationRegion {region}."
            )
        assignment = assignments[-1]
        mask = asl_integer(assignment.group("mask"))
        if mask <= 0 or mask & (mask - 1):
            raise FixError(
                f"SDTL value for {label} is not a single bit: 0x{mask:X}."
            )
        nearby_condition = before[max(0, assignment.start() - 700) : assignment.start()]
        tested_masks = [asl_integer(m.group("mask")) for m in mask_test_re.finditer(nearby_condition)]
        if mask not in tested_masks:
            raise FixError(
                f"The SDTL assignment 0x{mask:X} for {label} is not guarded by a "
                "matching SDTL bit test; refusing an unfamiliar CpuSsdt layout."
            )
        if label in seen_labels:
            raise FixError(f"Loaded CpuSsdt sub-table {label} was mapped more than once.")
        seen_labels.add(label)
        mappings.append((label, mask, region, ",".join(loaded_ids[label])))

    if not mappings:
        available = ", ".join(sorted(loaded_ids)) or "none"
        raise FixError(
            "No CpuSsdt dynamic Load() could be matched to an SSDT already loaded by "
            f"the kernel. Loaded OEM Table IDs: {available}."
        )

    mask = 0
    for _, bit, _, _ in mappings:
        if mask & bit:
            raise FixError(f"The same SDTL bit 0x{bit:X} maps to multiple loaded tables.")
        mask |= bit
    return mask, sorted(mappings)


def patch_cpussdt_text(
    text: str,
    loaded_ids: dict[str, list[str]],
) -> tuple[str, int, list[tuple[str, int, str, str]]]:
    if not re.search(r"\bGCAP\b", text):
        raise FixError("CpuSsdt does not contain GCAP; refusing an unfamiliar table.")

    mask, mappings = derive_cpussdt_sdtl_mask(text, loaded_ids)
    text = increment_definition_revision(text, "SSDT", "CpuSsdt")
    pattern = re.compile(
        r'^(?P<indent>\s*)Name\s*\(\s*(?P<root>\\?)SDTL\s*,\s*Zero\s*\)\s*$',
        re.MULTILINE,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise FixError(
            "Expected exactly one 'Name (\\SDTL, Zero)' in CpuSsdt, "
            f"found {len(matches)}."
        )
    match = matches[0]
    replacement = f"{match.group('indent')}Name ({match.group('root')}SDTL, 0x{mask:08X})"
    patched = text[: match.start()] + replacement + text[match.end() :]

    if not re.search(
        rf"Name\s*\(\s*\\?SDTL\s*,\s*0x{mask:08X}\s*\)",
        patched,
        re.IGNORECASE,
    ):
        raise FixError("Internal validation failed: derived SDTL value was not found.")
    return patched, mask, mappings


# ---------------------------------------------------------------------------
# DSDT fix (the _OSC buffer-overflow bug): patched directly in AML bytes
# instead of via disassemble/edit-ASL/recompile -- see the module docstring
# for why. Layout, top to bottom:
#   1. generic AML primitives (PkgLength, integers, NameSegs, UUID buffers)
#   2. the two _OSC shapes real firmware uses ("Family A" / "Family B") and
#      the fixed replacement bytes for each
#   3. find_osc_replacements() / patch_dsdt_aml(): tie 1+2 together into the
#      actual byte-level patch
#   4. a second, independent check of the same patch via iasl's decompiler
# ---------------------------------------------------------------------------

# Used only in the two regexes below, which match an ASL integer literal
# however iasl chose to render it (bare "4"/"8" or "0x04"/"0x08").
_OFFSET_4_RE = r"(?:0x0?4|4)"
_OFFSET_8_RE = r"(?:0x0?8|8)"


def validate_acpi_binary(data: bytes, expected_signature: bytes) -> None:
    """Validate the standard 36-byte ACPI header and whole-table checksum."""
    if len(data) < 36:
        raise FixError(f"ACPI table is too short: {len(data)} bytes.")
    if data[:4] != expected_signature:
        raise FixError(
            f"Expected ACPI signature {expected_signature!r}, found {data[:4]!r}."
        )
    declared_length = struct.unpack_from("<I", data, 4)[0]
    if declared_length != len(data):
        raise FixError(
            f"ACPI header length is {declared_length}, but file size is {len(data)}."
        )
    if sum(data) & 0xFF:
        raise FixError("ACPI table checksum is invalid before patching.")


def aml_uuid_bytes(uuid_text: str) -> bytes:
    """Return the byte order used by AML Buffer(ToUUID(...))."""
    return uuidlib.UUID(uuid_text).bytes_le


def decode_pkg_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an AML PkgLength and return (length, encoded-byte-count).

    Per the ACPI spec, the lead byte's top 2 bits say how many extra bytes
    follow (0-3). With none, the whole lead byte (6 bits) is the length. With
    extra bytes, only the *low nibble* of the lead byte is used and the extra
    bytes each contribute 8 more bits above it -- the middle 2 bits of the
    lead byte are unused padding in that case.
    """
    if offset >= len(data):
        raise ValueError("PkgLength starts beyond end of data")
    lead = data[offset]
    follow = lead >> 6
    size = follow + 1
    if offset + size > len(data):
        raise ValueError("Truncated AML PkgLength")
    if follow == 0:
        return lead & 0x3F, 1
    length = lead & 0x0F
    for index in range(follow):
        length |= data[offset + 1 + index] << (4 + 8 * index)
    return length, size


def iter_simple_methods(data: bytes, name: bytes = b"_OSC") -> list[AmlMethod]:
    """Find MethodOp objects whose NameString is a simple four-byte NameSeg.

    This is a brute-force scan for the MethodOp byte at every offset, not a
    real namespace-aware AML walk -- deliberately so, since we don't care
    which scope a method lives in, only whether its body matches one of the
    documented broken _OSC shapes. A MethodOp byte that isn't really a
    MethodOp (e.g. it's the middle of some other object's data) will almost
    certainly fail the PkgLength/name/flags checks below and simply be
    skipped, and every method this returns is re-validated structurally by
    its caller before anything gets patched.
    """
    result: list[AmlMethod] = []
    for start in range(36, max(36, len(data) - 8)):
        if data[start] != 0x14:  # MethodOp
            continue
        try:
            pkg_length, pkg_size = decode_pkg_length(data, start + 1)
        except ValueError:
            continue
        end = start + 1 + pkg_length
        name_offset = start + 1 + pkg_size
        flags_offset = name_offset + 4
        if end > len(data) or flags_offset >= end:
            continue
        if data[name_offset : name_offset + 4] != name:
            continue
        result.append(
            AmlMethod(
                start=start,
                pkg_length=pkg_length,
                pkg_length_size=pkg_size,
                flags=data[flags_offset],
                body_start=flags_offset + 1,
                end=end,
            )
        )
    return result


class AmlCursor:
    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def need(self, count: int) -> None:
        if self.pos + count > self.end:
            raise ValueError("Unexpected end of AML object")

    def byte(self, expected: int | None = None) -> int:
        self.need(1)
        value = self.data[self.pos]
        if expected is not None and value != expected:
            raise ValueError(
                f"Expected AML opcode 0x{expected:02X} at +0x{self.pos:X}, "
                f"found 0x{value:02X}"
            )
        self.pos += 1
        return value

    def nameseg(self, expected: bytes | None = None) -> bytes:
        self.need(4)
        value = self.data[self.pos : self.pos + 4]
        if expected is not None and value != expected:
            raise ValueError(
                f"Expected NameSeg {expected!r} at +0x{self.pos:X}, found {value!r}"
            )
        self.pos += 4
        return value

    def integer(self) -> int:
        opcode = self.byte()
        if opcode == 0x00:
            return 0
        if opcode == 0x01:
            return 1
        if opcode == 0xFF:
            return 0xFFFFFFFFFFFFFFFF
        widths = {0x0A: 1, 0x0B: 2, 0x0C: 4, 0x0E: 8}
        if opcode not in widths:
            raise ValueError(f"Unsupported AML integer opcode 0x{opcode:02X}")
        width = widths[opcode]
        self.need(width)
        value = int.from_bytes(self.data[self.pos : self.pos + width], "little")
        self.pos += width
        return value

    def package_end(self) -> int:
        length, size = decode_pkg_length(self.data, self.pos)
        package_start = self.pos
        self.pos += size
        end = package_start + length
        if end > self.end or end < self.pos:
            raise ValueError("Invalid nested AML package length")
        return end


def parse_uuid_buffer(cursor: AmlCursor, expected_uuid: str) -> None:
    cursor.byte(0x11)  # BufferOp
    buffer_end = cursor.package_end()
    if cursor.integer() != 16:
        raise ValueError("UUID buffer does not declare a 16-byte size")
    expected = aml_uuid_bytes(expected_uuid)
    cursor.need(16)
    value = cursor.data[cursor.pos : cursor.pos + 16]
    cursor.pos += 16
    if value != expected:
        raise ValueError("UUID buffer does not contain the expected UUID")
    if cursor.pos != buffer_end:
        raise ValueError("Unexpected data in UUID buffer")


def read_uuid_buffer_bytes(cursor: AmlCursor) -> bytes:
    """Like parse_uuid_buffer(), but returns whatever 16-byte UUID is present
    instead of checking it against an expected value."""
    cursor.byte(0x11)  # BufferOp
    buffer_end = cursor.package_end()
    if cursor.integer() != 16:
        raise ValueError("Buffer does not declare a 16-byte size")
    cursor.need(16)
    value = cursor.data[cursor.pos : cursor.pos + 16]
    cursor.pos += 16
    if cursor.pos != buffer_end:
        raise ValueError("Unexpected data in UUID buffer")
    return value


def is_valid_nameseg(value: bytes) -> bool:
    """AML NameSegs are exactly 4 bytes: [A-Z_] followed by three [A-Z0-9_]."""
    if len(value) != 4:
        return False

    def ok(b: int, allow_digit: bool) -> bool:
        return 0x41 <= b <= 0x5A or b == 0x5F or (allow_digit and 0x30 <= b <= 0x39)

    return ok(value[0], False) and all(ok(b, True) for b in value[1:])


def find_named_uuid(data: bytes, nameseg: bytes) -> str:
    """Find Name(<nameseg>, Buffer(ToUUID(...))) anywhere in `data` and return
    which of the two documented _OSC UUIDs it holds.

    Used for the "Family B" DSDT shape, where the _OSC method compares Arg0
    against a pre-declared named UUID object instead of an inline literal
    (see parse_family_b_osc_prologue()). This only reads the Name(...)
    declaration; it never touches it.
    """
    marker = b"\x08" + nameseg  # NameOp + NameSeg
    matches: list[bytes] = []
    start = 0
    while True:
        idx = data.find(marker, start)
        if idx == -1:
            break
        try:
            value = read_uuid_buffer_bytes(AmlCursor(data, idx + len(marker)))
        except ValueError:
            start = idx + 1
            continue
        matches.append(value)
        start = idx + 1

    if not matches:
        raise ValueError(
            f"No Name({nameseg.decode('ascii', 'replace')}, Buffer(ToUUID(...))) "
            "declaration was found"
        )
    unique = set(matches)
    if len(unique) != 1:
        raise ValueError(
            f"Name {nameseg.decode('ascii', 'replace')!r} is declared with "
            f"{len(unique)} different UUID values"
        )
    value = next(iter(unique))
    for uuid_text in (UUID_SB_OSC, UUID_PCI0_OSC):
        if value == aml_uuid_bytes(uuid_text):
            return uuid_text
    raise ValueError(
        f"Name {nameseg.decode('ascii', 'replace')!r} holds UUID "
        f"{uuidlib.UUID(bytes_le=value)}, which is neither documented _OSC UUID"
    )


def parse_create_dword_field(
    cursor: AmlCursor,
    expected_index: int,
    expected_name: bytes,
) -> None:
    cursor.byte(0x8A)  # CreateDWordFieldOp
    cursor.byte(0x60)  # Local0
    if cursor.integer() != expected_index:
        raise ValueError(f"CreateDWordField index is not {expected_index}")
    cursor.nameseg(expected_name)


def parse_documented_broken_osc_body(body: bytes, uuid_text: str) -> None:
    """Accept the documented broken _OSC semantics, independent of Method PkgLength."""
    cursor = AmlCursor(body)
    cursor.byte(0xA0)  # IfOp
    if_end = cursor.package_end()
    if_cursor = AmlCursor(body, cursor.pos, if_end)
    if_cursor.byte(0x93)  # LEqualOp
    if_cursor.byte(0x68)  # Arg0
    parse_uuid_buffer(if_cursor, uuid_text)
    if_cursor.byte(0x70)  # StoreOp
    if_cursor.byte(0x6B)  # Arg3
    if_cursor.byte(0x60)  # Local0
    parse_create_dword_field(if_cursor, 0, b"CDW1")
    parse_create_dword_field(if_cursor, 4, b"CDW2")
    parse_create_dword_field(if_cursor, 8, b"CDW3")
    if if_cursor.pos != if_end:
        raise ValueError("Unexpected AML terms inside the _OSC If block")
    cursor.pos = if_end

    cursor.byte(0xA1)  # ElseOp
    else_end = cursor.package_end()
    else_cursor = AmlCursor(body, cursor.pos, else_end)
    else_cursor.byte(0x7D)  # OrOp
    else_cursor.nameseg(b"CDW1")
    if else_cursor.integer() != 4:
        raise ValueError("_OSC Else branch does not OR status bit 0x04")
    else_cursor.nameseg(b"CDW1")
    if else_cursor.pos != else_end:
        raise ValueError("Unexpected AML terms inside the _OSC Else block")
    cursor.pos = else_end

    cursor.byte(0xA4)  # ReturnOp
    cursor.byte(0x60)  # Local0
    while cursor.pos < cursor.end and body[cursor.pos] == 0xA3:  # tolerate firmware NoopOp padding
        cursor.pos += 1
    if cursor.pos != cursor.end:
        raise ValueError("Unexpected AML terms after Return(Local0)")


def fixed_osc_body(uuid_text: str, target_length: int) -> bytes:
    """Build the documented fixed method body and pad it without changing size."""
    logical = (
        b"\x70\x6B\x60"                 # Store(Arg3, Local0)
        + b"\x8A\x60\x00CDW1"           # CreateDWordField(Local0, 0, CDW1)
        + b"\xA0\x1F\x93\x68\x11\x13\x0A\x10"
        + aml_uuid_bytes(uuid_text)
        + b"\x8A\x60\x0A\x04CDW2"      # in-bounds CDW2 only
        + b"\xA1\x0C\x7DCDW1\x0A\x04CDW1"
        + b"\xA4\x60"
    )
    if len(logical) > target_length:
        raise FixError(
            f"The fixed _OSC body needs {len(logical)} bytes, but firmware provides "
            f"only {target_length}."
        )
    padding = b"\xA3" * (target_length - len(logical))
    # Keep Return(Local0) last and place harmless NoopOp padding immediately before it.
    return logical[:-2] + padding + logical[-2:]


def parse_family_b_osc_prologue(body: bytes) -> bytes:
    """Match Apple's PCI-hotplug-aware _OSC shape ("Family B"): Local0=Arg3
    and all three CreateDWordField calls -- including the out-of-bounds
    CDW3 -- happen unconditionally before any UUID check, and the UUID
    comparison further down references a named Buffer(ToUUID(...)) object
    (resolved separately via find_named_uuid()) instead of an inline
    literal. Real firmware from MacBookPro15,1, MacBookPro16,1 and
    Macmini8,1 uses this exact 193-byte method body, implementing NHPG/NPME
    hotplug notifications and OSDW/OSCC/CTRL/SUPP negotiation around the
    same CDW3 overflow bug the simple "Family A" shape has.

    Returns the 4-byte NameSeg compared against Arg0.
    """
    cursor = AmlCursor(body)
    cursor.byte(0x70)  # StoreOp
    cursor.byte(0x6B)  # Arg3
    cursor.byte(0x60)  # Local0
    parse_create_dword_field(cursor, 0, b"CDW1")
    parse_create_dword_field(cursor, 4, b"CDW2")
    parse_create_dword_field(cursor, 8, b"CDW3")
    prologue_end = cursor.pos

    rest = body[prologue_end:]
    names: set[bytes] = set()
    search_from = 0
    marker = b"\x93\x68"  # LEqualOp, Arg0
    while True:
        idx = rest.find(marker, search_from)
        if idx == -1:
            break
        nameseg = rest[idx + 2 : idx + 6]
        if is_valid_nameseg(nameseg):
            names.add(nameseg)
        search_from = idx + 1

    if not names:
        raise ValueError(
            "No Arg0-compared name reference found after the unconditional prologue"
        )
    if len(names) > 1:
        sorted_names = sorted(n.decode("ascii", "replace") for n in names)
        raise ValueError(f"Multiple different names compared against Arg0: {sorted_names}")
    return next(iter(names))


def _pkg_length_byte(payload_len: int) -> bytes:
    # +1 because PkgLength counts its own encoded byte(s) too (see
    # decode_pkg_length's docstring). 0x3F is the largest length a single
    # PkgLength byte can hold (top 2 bits must stay 0 to mean "no extra
    # bytes follow") -- comfortably more than our fixed skeleton ever needs.
    total = payload_len + 1
    if total > 0x3F:
        raise FixError("Internal error: fixed _OSC skeleton package exceeds 1-byte PkgLength.")
    return bytes([total])


def fixed_osc_body_named(nameseg: bytes, target_length: int) -> bytes:
    """Build the fixed method body for the "Family B" shape: the same
    minimal documented-fix skeleton as fixed_osc_body(), but comparing Arg0
    against the pre-existing named UUID object instead of an inline literal
    -- the Name(...) declaration itself lives outside this method body and
    is left untouched."""
    if_payload = b"\x93\x68" + nameseg + b"\x8A\x60\x0A\x04CDW2"
    else_payload = b"\x7DCDW1\x0A\x04CDW1"
    logical = (
        b"\x70\x6B\x60"  # Store(Arg3, Local0)
        + b"\x8A\x60\x00CDW1"  # CreateDWordField(Local0, 0, CDW1)
        + b"\xA0" + _pkg_length_byte(len(if_payload)) + if_payload
        + b"\xA1" + _pkg_length_byte(len(else_payload)) + else_payload
        + b"\xA4\x60"  # Return(Local0)
    )
    if len(logical) > target_length:
        raise FixError(
            f"The fixed _OSC body needs {len(logical)} bytes, but firmware provides "
            f"only {target_length}."
        )
    padding = b"\xA3" * (target_length - len(logical))
    return logical[:-2] + padding + logical[-2:]


def find_osc_replacements(
    data: bytes,
) -> list[tuple[str, AmlMethod, str, bytes | None]]:
    """Find every documented-broken _OSC method for either documented UUID,
    in either of the two AML shapes real T2 firmware uses ("Family A":
    parse_documented_broken_osc_body(); "Family B":
    parse_family_b_osc_prologue()).

    Real hardware only ever has a method for one or both of the two
    documented UUIDs, in one shape or the other -- not necessarily both --
    so this returns whatever it can resolve rather than demanding both up
    front; patch_dsdt_aml() decides whether the result is enough to
    proceed. A method that doesn't match either shape at all is silently
    skipped (with a diagnostic kept for the final error message if nothing
    at all resolves); the manual README steps remain the fallback for
    DSDTs this doesn't recognize.
    """
    resolved: dict[str, tuple[AmlMethod, str, bytes | None]] = {}
    diagnostics: list[str] = []

    for method in iter_simple_methods(data, b"_OSC"):
        if method.flags != 0x0C:
            diagnostics.append(
                f"_OSC at 0x{method.start:X}: unexpected Method flags 0x{method.flags:02X}"
            )
            continue
        body = data[method.body_start : method.end]

        match: tuple[str, str, bytes | None] | None = None
        for uuid_text in (UUID_SB_OSC, UUID_PCI0_OSC):
            if aml_uuid_bytes(uuid_text) not in body:
                continue
            try:
                parse_documented_broken_osc_body(body, uuid_text)
            except ValueError as exc:
                diagnostics.append(f"_OSC at 0x{method.start:X} ({uuid_text}, family A): {exc}")
                continue
            match = (uuid_text, "A", None)
            break

        if match is None:
            try:
                nameseg = parse_family_b_osc_prologue(body)
            except ValueError as exc:
                diagnostics.append(f"_OSC at 0x{method.start:X} (family B): {exc}")
                continue
            try:
                uuid_text = find_named_uuid(data, nameseg)
            except ValueError as exc:
                diagnostics.append(
                    f"_OSC at 0x{method.start:X} (family B, name "
                    f"{nameseg.decode('ascii', 'replace')!r}): {exc}"
                )
                continue
            match = (uuid_text, "B", nameseg)

        uuid_text, kind, extra = match
        if uuid_text in resolved:
            raise FixError(
                f"Multiple documented broken _OSC methods resolved to UUID {uuid_text}: "
                f"0x{resolved[uuid_text][0].start:X} and 0x{method.start:X}."
            )
        resolved[uuid_text] = (method, kind, extra)

    if not resolved:
        details = "; ".join(diagnostics) if diagnostics else "no _OSC methods found at all"
        raise FixError(
            "No _OSC method matched either documented broken AML shape for either "
            f"documented UUID ({details}). This model's DSDT is not patched "
            "automatically; follow the manual README steps for it instead."
        )

    for uuid_text in (UUID_SB_OSC, UUID_PCI0_OSC):
        if uuid_text not in resolved:
            log(
                f"No _OSC method exists for UUID {uuid_text} on this DSDT; nothing to patch "
                "for it (normal on some models, not an error)."
            )

    return [(uuid_text, method, kind, extra) for uuid_text, (method, kind, extra) in resolved.items()]


def patch_dsdt_aml(
    original: bytes,
) -> tuple[bytes, list[tuple[str, int, int, str, str]], int, int]:
    """Apply all semantically validated _OSC replacements and refresh the header.

    Returns (patched_bytes, replacements, old_revision, new_revision), where
    each replacement is (uuid_text, method_start, method_length, kind, anchor)
    -- anchor is the UUID text for "Family A" methods or the compared NameSeg
    (e.g. "GUID") for "Family B" ones, and is what an independent disassembly
    check can search for to relocate the same method in decompiled text.
    """
    validate_acpi_binary(original, b"DSDT")
    resolved = find_osc_replacements(original)

    def fixed_body_for(kind: str, uuid_text: str, extra: bytes | None, length: int) -> bytes:
        if kind == "A":
            return fixed_osc_body(uuid_text, length)
        assert extra is not None
        return fixed_osc_body_named(extra, length)

    patched = bytearray(original)
    replacements: list[tuple[str, int, int, str, str]] = []
    for uuid_text, method, kind, extra in resolved:
        replacement = fixed_body_for(kind, uuid_text, extra, method.body_length)
        patched[method.body_start : method.end] = replacement
        anchor = uuid_text if kind == "A" else extra.decode("ascii")
        replacements.append((uuid_text, method.start, method.end - method.start, kind, anchor))

    # Bumping the OEM revision (header offset 24, a 4-byte LE field) is what
    # makes the kernel prefer this override over the firmware's own DSDT.
    old_revision = struct.unpack_from("<I", patched, 24)[0]
    if old_revision >= 0xFFFFFFFF:
        raise FixError("DSDT OEM revision cannot be incremented beyond 0xFFFFFFFF.")
    new_revision = old_revision + 1
    struct.pack_into("<I", patched, 24, new_revision)

    # ACPI tables are valid iff the unsigned byte-sum of the whole table is
    # 0 mod 256. Zero the checksum byte (header offset 9) first so it doesn't
    # contribute its old value to its own recomputation.
    patched[9] = 0
    patched[9] = (-sum(patched)) & 0xFF
    result = bytes(patched)

    if len(result) != len(original):
        raise FixError("Internal validation failed: DSDT size changed.")
    if struct.unpack_from("<I", result, 4)[0] != len(result):
        raise FixError("Internal validation failed: DSDT header length changed or is invalid.")
    if sum(result) & 0xFF:
        raise FixError("Internal validation failed: patched DSDT checksum is invalid.")

    for uuid_text, method, kind, extra in resolved:
        expected = fixed_body_for(kind, uuid_text, extra, method.body_length)
        if result[method.body_start : method.end] != expected:
            raise FixError(f"Internal validation failed for patched _OSC {uuid_text}.")

    # Belt-and-suspenders: confirm byte-for-byte that nothing changed outside
    # the patched method bodies and the header fields we intentionally
    # touched above. A bug in the slice arithmetic above would corrupt
    # unrelated parts of the table; this catches that before deployment
    # rather than trusting the slicing was correct.
    changed = [index for index, (before, after) in enumerate(zip(original, result)) if before != after]
    allowed: set[int] = {9} | set(range(24, 28))
    for _, method, _, _ in resolved:
        allowed.update(range(method.body_start, method.end))
    unexpected = [index for index in changed if index not in allowed]
    if unexpected:
        preview = ", ".join(hex(index) for index in unexpected[:8])
        raise FixError(f"Internal validation failed: unexpected DSDT byte changes at {preview}.")

    return result, replacements, old_revision, new_revision


# ---------------------------------------------------------------------------
# Independent validation of the DSDT patch: re-decompile the patched table
# with iasl and check the *text* shows the fix, using regexes that are
# deliberately not shared with the AmlCursor byte parser above. A bug that
# exists in both the byte-level patcher and this checker would slip through
# either way, but a bug in just one of them will not.
# ---------------------------------------------------------------------------


def locate_osc_method_body(text: str, anchor: str, *, source_label: str) -> str:
    """Return the brace-delimited body of the _OSC method whose body contains
    `anchor` -- either a UUID string (the "Family A" inline-literal shape) or
    a bare NameSeg like "GUID" (the "Family B" named-reference shape).

    Scans every `Method (_OSC ...)` in the text and returns the first whose
    body contains the anchor, rather than searching backward from a single
    occurrence of the anchor in the whole text: for Family B, the anchor
    NameSeg's own Name(...) declaration textually precedes the method, so a
    backward search from that declaration would never find the method at all.
    """
    clean = strip_asl_comments(text)
    anchor_re = re.compile(re.escape(anchor), re.IGNORECASE)
    method_pattern = re.compile(r"Method\s*\(\s*_OSC\b")
    for match in method_pattern.finditer(clean):
        brace_open = clean.find("{", match.end())
        if brace_open == -1:
            continue
        brace_close = find_matching_brace(clean, brace_open)
        body = clean[match.start() : brace_close + 1]
        if anchor_re.search(body):
            return body
    raise FixError(
        f"Could not locate an _OSC Method in {source_label} whose body references "
        f"{anchor!r}."
    )


def assert_disassembled_osc_is_fixed(text: str, anchor: str, *, source_label: str) -> None:
    """Confirm, via iasl's own decompiler, that the patched method matches the
    documented fix: CDW1 created before the If, CDW2 only inside the If,
    CDW1 |= 0x04 in the Else, and no CDW3 anywhere."""
    body = locate_osc_method_body(text, anchor, source_label=source_label)

    if re.search(r"\bCDW3\b", body):
        raise FixError(
            f"{source_label} still shows CDW3 for _OSC ({anchor}) after patching; "
            "the text rewrite did not take effect as intended."
        )

    create_cdw1 = re.search(
        r"CreateDWordField\s*\(\s*Local0\s*,\s*Zero\s*,\s*CDW1\s*\)", body, re.IGNORECASE
    )
    if not create_cdw1:
        raise FixError(
            f"{source_label} does not show CDW1 being created for _OSC ({anchor}) "
            "after patching."
        )

    if_match = re.search(r"\bIf\s*\(", body, re.IGNORECASE)
    if not if_match or if_match.start() < create_cdw1.start():
        raise FixError(
            f"{source_label} does not show CDW1 being created before the If block "
            f"for _OSC ({anchor}) after patching; both branches must see CDW1."
        )

    if not re.search(
        rf"CreateDWordField\s*\(\s*Local0\s*,\s*{_OFFSET_4_RE}\s*,\s*CDW2\s*\)",
        body,
        re.IGNORECASE,
    ):
        raise FixError(
            f"{source_label} does not show CDW2 being created inside the If branch "
            f"for _OSC ({anchor}) after patching."
        )

    if not re.search(
        rf"CDW1\s*\|=\s*{_OFFSET_4_RE}|Or\s*\(\s*CDW1\s*,\s*{_OFFSET_4_RE}\s*,\s*CDW1\s*\)",
        body,
        re.IGNORECASE,
    ):
        raise FixError(
            f"{source_label} does not show the Else branch OR'ing CDW1 with 0x04 "
            f"for _OSC ({anchor}) after patching."
        )


def assert_disassembled_osc_is_the_documented_bug(
    text: str, anchor: str, *, source_label: str
) -> None:
    """Sanity-check that the *unmodified* firmware DSDT still shows the
    documented CDW3 overflow, so we know the baseline we are comparing
    against is actually the bug the patch targets."""
    body = locate_osc_method_body(text, anchor, source_label=source_label)
    if not re.search(r"\bCDW3\b", body):
        raise FixError(
            f"Independent iasl disassembly of {source_label} does not show the "
            f"documented CDW3 buffer overflow for _OSC ({anchor}); the AML-level "
            "patch and the disassembly view of this table disagree about the "
            "original shape, refusing to deploy."
        )


def disassemble_only(aml: Path) -> tuple[str, int, int]:
    """Run `iasl -d` as an independent structural check; never recompiles.

    This is deliberately not a full `-tc` round-trip: recompiling an Apple
    DSDT from scratch is unreliable across models (unrelated constructs like
    legacy VarPackage brightness tables can fail to round-trip even though
    they have nothing to do with the _OSC fix). Disassembly alone is a much
    weaker requirement -- iasl's decompiler tolerates forward references and
    duplicate namespace objects that its compiler rejects -- but it is still
    an independent second parser of the AML patch_dsdt_aml() hand-built,
    distinct from the AmlCursor code above.
    """
    proc = run(["iasl", "-d", aml.name], cwd=aml.parent, check=False, echo_output=True)
    dsl = aml.with_suffix(".dsl")
    if not dsl.is_file():
        raise FixError(
            f"iasl could not disassemble {aml.name} for independent validation; "
            f"refusing to trust the binary patch:\n{proc.stdout.strip()}"
        )
    summaries = re.findall(r"(\d+)\s+Errors?,\s+(\d+)\s+Warnings?", proc.stdout, re.I)
    errors, warnings = (int(value) for value in summaries[-1]) if summaries else (0, 0)
    text = dsl.read_text(encoding="utf-8", errors="replace")
    return text, errors, warnings


def validate_patched_dsdt_with_iasl(
    baseline_aml: Path,
    patched_aml: Path,
    replacements: Sequence[tuple[str, int, int, str, str]],
) -> None:
    """Independently re-check the hand-built AML patch using iasl's decompiler.

    This does not replace the byte-level checks in patch_dsdt_aml(); it is a
    second, differently-implemented opinion. It compares the patched table
    against the machine's own unmodified DSDT rather than a fixed expectation,
    so pre-existing firmware quirks (unresolved externals, vendor remarks)
    don't cause false failures as long as the patch doesn't add new ones.

    `replacements` is patch_dsdt_aml()'s return value: each entry's `anchor`
    (last element) is what locates the same method in decompiled text --
    the UUID string for "Family A" methods, or the compared NameSeg (e.g.
    "GUID") for "Family B" ones.
    """
    baseline_text, baseline_errors, baseline_warnings = disassemble_only(baseline_aml)
    patched_text, patched_errors, patched_warnings = disassemble_only(patched_aml)

    if patched_errors > baseline_errors:
        raise FixError(
            "Independent iasl disassembly reports more errors for the patched DSDT "
            f"({patched_errors}) than for the unmodified firmware DSDT ({baseline_errors}); "
            "refusing to deploy."
        )
    if patched_warnings > baseline_warnings:
        raise FixError(
            "Independent iasl disassembly reports more warnings for the patched DSDT "
            f"({patched_warnings}) than for the unmodified firmware DSDT "
            f"({baseline_warnings}); refusing to deploy."
        )

    for _, _, _, _, anchor in replacements:
        assert_disassembled_osc_is_the_documented_bug(
            baseline_text, anchor, source_label="the unmodified DSDT"
        )
        assert_disassembled_osc_is_fixed(
            patched_text, anchor, source_label="the patched DSDT"
        )

    log(
        f"Independent iasl disassembly confirms the documented _OSC fix for "
        f"{len(replacements)} method(s) and introduces no new diagnostics "
        f"(baseline {baseline_errors} error(s)/{baseline_warnings} warning(s), "
        f"patched {patched_errors} error(s)/{patched_warnings} warning(s))."
    )


# ---------------------------------------------------------------------------
# Building each table: compile the patched CpuSSDT ASL, and drive the DSDT
# byte-patch + independent validation above into a deployable BuiltTable each
# ---------------------------------------------------------------------------


def write_patched_dsl(path: Path, patched: str) -> None:
    path.write_text(patched, encoding="utf-8", newline="\n")
    path.chmod(0o600)


def compile_dsl(dsl: Path) -> CompileResult:
    proc = run(
        ["iasl", "-tc", dsl.name],
        cwd=dsl.parent,
        check=False,
        echo_output=True,
    )
    summaries = re.findall(
        r"(\d+)\s+Errors?,\s+(\d+)\s+Warnings?",
        proc.stdout,
        re.I,
    )
    if not summaries:
        raise FixError("Could not verify the iasl error/warning summary; refusing deployment.")
    errors, warnings = (int(value) for value in summaries[-1])
    warning_codes: Counter[str] = Counter(
        re.findall(r"^Warning\s+(\d+)\s+-", proc.stdout, re.MULTILINE)
    )
    aml = dsl.with_suffix(".aml")
    if errors == 0 and (not aml.is_file() or aml.stat().st_size == 0):
        raise FixError(f"Compiled AML file is missing or empty: {aml}")
    return CompileResult(aml, errors, warnings, warning_codes)


def require_clean_compile(result: CompileResult, table_name: str) -> Path:
    if result.errors != 0 or result.warnings != 0:
        raise FixError(
            f"iasl reported {result.errors} error(s) and {result.warnings} warning(s) "
            f"while compiling {table_name}; expected 0 Errors and 0 Warnings."
        )
    return result.aml

def cpussdt_deploy_name(product_name: str) -> str:
    match = re.search(r"(?:MacBookPro|MacBookAir|Macmini|iMacPro|iMac|MacPro)(\d+),(\d+)", product_name, re.I)
    if match:
        name = f"{match.group(1)}{match.group(2)}CpuSSDT.aml"
    else:
        name = "CpuSSDT.aml"
    if len(name) > 17:
        raise FixError(f"Generated CpuSSDT filename exceeds 17 characters: {name}")
    return name


def build_cpussdt(workdir: Path, product_name: str) -> BuiltTable:
    workdir = workdir / "cpussdt"
    workdir.mkdir(mode=0o700)
    source = find_cpussdt_table()
    log(f"CpuSsdt source table: {source}")
    local_source, dsl = copy_and_disassemble(source, workdir)
    original_copy = Path(str(dsl) + ".orig")
    shutil.copy2(dsl, original_copy)
    original = dsl.read_text(encoding="utf-8", errors="strict")
    loaded_ids = loaded_ssdt_table_ids()
    patched, mask, mappings = patch_cpussdt_text(original, loaded_ids)
    log(f"Derived CpuSSDT SDTL mask from loaded local tables: 0x{mask:08X}")
    if VERBOSE:
        for label, bit, region, files in mappings:
            log(f"  {label}: SDTL bit 0x{bit:X}, region {region}, loaded as {files}")
    write_patched_dsl(dsl, patched)
    aml = require_clean_compile(compile_dsl(dsl), "CpuSSDT")
    report = workdir / "CpuSSDT.patch-report.txt"
    report_lines = [
        "T2 ACPI CpuSSDT patch report",
        "",
        f"Source: {source}",
        f"Derived SDTL mask: 0x{mask:08X}",
        "",
        "Bits set only for SSDT package entries whose OEM Table ID is already",
        "present as a kernel-loaded SSDT:",
    ]
    for label, bit, region, files in mappings:
        report_lines.append(f"  {label}: bit 0x{bit:X}, region {region}, files {files}")
    report.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    report.chmod(0o600)
    return BuiltTable("CpuSSDT", local_source, report, aml, cpussdt_deploy_name(product_name))


def build_dsdt(workdir: Path) -> BuiltTable:
    dsdt_dir = workdir / "dsdt"
    dsdt_dir.mkdir(mode=0o700)
    source = ACPI_TABLE_DIR / "DSDT"
    if not source.is_file():
        raise FixError(f"DSDT table is missing: {source}")

    log(f"DSDT source table: {source}")
    local_source = dsdt_dir / "DSDT.original.aml"
    shutil.copy2(source, local_source)
    local_source.chmod(0o600)
    original = local_source.read_bytes()

    patched, replacements, old_revision, new_revision = patch_dsdt_aml(original)
    aml = dsdt_dir / "DSDT.patched.aml"
    aml.write_bytes(patched)
    aml.chmod(0o600)

    log("Independently re-checking the patch by disassembling it with iasl (no recompile)...")
    validate_patched_dsdt_with_iasl(local_source, aml, replacements)

    family_names = {"A": "inline UUID literal", "B": "PCI-hotplug, named UUID reference"}
    report = dsdt_dir / "DSDT.patch-report.txt"
    lines = [
        "T2 ACPI DSDT binary patch report",
        "",
        f"Source: {source}",
        "Patched directly in AML bytes (not via disassemble/edit-ASL/recompile,",
        "which is unreliable across models for the reasons explained in this",
        "script's module docstring). Verified by an independent iasl disassembly",
        "(no recompile) rather than trusting only the hand-written AML parser.",
        "",
        f"OEM revision: 0x{old_revision:08X} -> 0x{new_revision:08X}",
        "",
        f"{len(replacements)} of the 2 documented _OSC UUIDs had a matching method on",
        "this DSDT (some models only implement one of the two -- that is normal, not",
        "an error). Each matched method body was replaced so that:",
        "  - Store(Arg3, Local0) and CreateDWordField(Local0, Zero, CDW1) run before",
        "    the UUID comparison, so both branches can see CDW1",
        "  - CreateDWordField(Local0, 0x04, CDW2) is the only field left inside the If",
        "  - CreateDWordField(Local0, 0x08, CDW3) (the out-of-bounds field) is removed",
        "  - the Else branch (CDW1 |= 0x04) is unchanged",
        "  - the method's total AML byte length, and every enclosing package length,",
        "    is unchanged; the freed space is backfilled with NoopOp padding",
    ]
    for uuid_text, start, length, kind, anchor in replacements:
        lines.append(
            f"  {uuid_text}: method at file offset 0x{start:X}, {length} bytes, "
            f"shape {kind} ({family_names[kind]}, anchor {anchor!r})"
        )
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report.chmod(0o600)

    log(f"Patched {len(replacements)} documented DSDT _OSC method(s) in AML and independently re-verified them.")
    return BuiltTable("DSDT", local_source, report, aml, "dsdt.aml")


# ---------------------------------------------------------------------------
# Deploying: copy the built tables into place, update the dracut config, and
# rebuild the initramfs -- backing up every file first so a failure partway
# through can roll the machine back to exactly its pre-deployment state.
# ---------------------------------------------------------------------------


def backup_path(path: Path, backup_dir: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    relative = path.relative_to("/")
    destination = backup_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if path.is_dir():
        shutil.copytree(path, destination, symlinks=True)
    else:
        shutil.copy2(path, destination, follow_symlinks=False)


def atomic_copy(source: Path, destination: Path, mode: int = 0o644) -> None:
    # Write to a temp file and rename over the target: a crash or power loss
    # mid-write can never leave a half-written ACPI override in place, since
    # rename() is atomic and the old file stays intact until it succeeds.
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp-acpi-fix")
    shutil.copyfile(source, temporary)
    temporary.chmod(mode)
    os.replace(temporary, destination)


def updated_dracut_conf(existing: str) -> str:
    retained: list[str] = []
    setting_re = re.compile(r"^\s*(acpi_override|acpi_table_dir)\s*=")
    for line in existing.splitlines():
        if not setting_re.match(line):
            retained.append(line)
    while retained and not retained[-1].strip():
        retained.pop()
    if retained:
        retained.append("")
    retained.extend(DRACUT_REQUIRED_LINES)
    return "\n".join(retained) + "\n"


def write_atomic_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-acpi-fix")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.chmod(mode)
    os.replace(temporary, path)


def restore_file(path: Path, backup_dir: Path, existed_before: bool) -> None:
    backup = backup_dir / path.relative_to("/")
    if existed_before:
        if not backup.exists() and not backup.is_symlink():
            raise FixError(f"Backup expected but missing during rollback: {backup}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if backup.is_dir():
            if path.exists():
                shutil.rmtree(path)
            shutil.copytree(backup, path, symlinks=True)
        else:
            shutil.copy2(backup, path, follow_symlinks=False)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def check_cpussdt_duplicates(target_name: str) -> None:
    if not DEPLOY_DIR.is_dir():
        return
    duplicates = [
        p for p in DEPLOY_DIR.iterdir()
        if p.is_file() and p.name.lower().endswith("cpussdt.aml") and p.name != target_name
    ]
    if duplicates:
        joined = ", ".join(str(p) for p in duplicates)
        raise FixError(
            "An existing differently named CpuSSDT override could cause duplicate table loading. "
            f"Move or remove it first: {joined}"
        )


# ---------------------------------------------------------------------------
# Per-strategy deployment: each factory returns the extra config file(s) to
# back up/restore alongside the tables themselves, a function that writes
# whatever config that strategy needs, and a function that rebuilds the
# initramfs. deploy_tables() below drives all three the same way regardless
# of strategy, so backup/rollback semantics are identical across strategies.
# Only the dracut factory has been exercised against a real deployment; see
# the module docstring.
# ---------------------------------------------------------------------------


def dracut_strategy() -> tuple[list[Path], Callable[[], None], Callable[[], None]]:
    def apply() -> None:
        old_conf = DRACUT_CONF.read_text(encoding="utf-8", errors="replace") if DRACUT_CONF.exists() else ""
        write_atomic_text(DRACUT_CONF, updated_dracut_conf(old_conf))
        log(f"Updated dracut configuration: {DRACUT_CONF}")

    def rebuild() -> None:
        run(["dracut", "--force"], echo_output=True)

    return [DRACUT_CONF], apply, rebuild


def initramfs_tools_hook_script() -> str:
    return (
        "#!/bin/sh\n"
        "# Installed by t2_acpi_fix.py: copies patched T2 Mac ACPI table\n"
        "# overrides into the initramfs at kernel/firmware/acpi/, which is where the\n"
        "# kernel's built-in ACPI table override mechanism (CONFIG_ACPI_TABLE_UPGRADE)\n"
        "# looks for them at boot, independent of which tool built the initramfs.\n"
        "set -e\n"
        "PREREQ=\"\"\n"
        "prereqs() { echo \"$PREREQ\"; }\n"
        "case \"$1\" in prereqs) prereqs; exit 0 ;; esac\n"
        ". /usr/share/initramfs-tools/hook-functions\n"
        f'mkdir -p "$DESTDIR/kernel/firmware/acpi"\n'
        f'for f in {DEPLOY_DIR}/*.aml; do\n'
        '    [ -e "$f" ] || continue\n'
        '    cp "$f" "$DESTDIR/kernel/firmware/acpi/"\n'
        "done\n"
    )


def initramfs_tools_strategy() -> tuple[list[Path], Callable[[], None], Callable[[], None]]:
    def apply() -> None:
        write_atomic_text(INITRAMFS_TOOLS_HOOK, initramfs_tools_hook_script(), mode=0o755)
        log(f"Installed initramfs-tools hook: {INITRAMFS_TOOLS_HOOK}")

    def rebuild() -> None:
        run(["update-initramfs", "-u"], echo_output=True)

    return [INITRAMFS_TOOLS_HOOK], apply, rebuild


def mkinitcpio_hook_script() -> str:
    return (
        "#!/bin/bash\n"
        "# Installed by t2_acpi_fix.py: copies patched T2 Mac ACPI table\n"
        "# overrides into the initramfs image at kernel/firmware/acpi/, which is where\n"
        "# the kernel's built-in ACPI table override mechanism (CONFIG_ACPI_TABLE_UPGRADE)\n"
        "# looks for them at boot, independent of which tool built the initramfs.\n"
        "build() {\n"
        "    local f\n"
        f"    for f in {DEPLOY_DIR}/*.aml; do\n"
        '        [[ -e "$f" ]] || continue\n'
        '        add_file "$f" "/kernel/firmware/acpi/$(basename "$f")"\n'
        "    done\n"
        "}\n"
        "\n"
        "help() {\n"
        "    cat <<HELPEOF\n"
        "Installs T2 Mac ACPI table overrides built by t2_acpi_fix.py.\n"
        "HELPEOF\n"
        "}\n"
    )


def add_mkinitcpio_hook(text: str, hook_name: str) -> str:
    pattern = re.compile(r"^(?P<prefix>\s*HOOKS=\()(?P<body>[^)]*)(?P<suffix>\)\s*)$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise FixError(f"Could not find a HOOKS=(...) line in {MKINITCPIO_CONF}.")
    hooks = match.group("body").split()
    if hook_name in hooks:
        return text
    hooks.append(hook_name)
    replacement = match.group("prefix") + " ".join(hooks) + match.group("suffix")
    return text[: match.start()] + replacement + text[match.end() :]


def mkinitcpio_strategy() -> tuple[list[Path], Callable[[], None], Callable[[], None]]:
    def apply() -> None:
        write_atomic_text(MKINITCPIO_HOOK_INSTALL, mkinitcpio_hook_script(), mode=0o755)
        log(f"Installed mkinitcpio hook: {MKINITCPIO_HOOK_INSTALL}")

        if not MKINITCPIO_CONF.is_file():
            raise FixError(f"mkinitcpio is installed, but {MKINITCPIO_CONF} is missing.")
        conf_text = MKINITCPIO_CONF.read_text(encoding="utf-8", errors="replace")
        updated = add_mkinitcpio_hook(conf_text, "acpi_t2_fix")
        if updated != conf_text:
            write_atomic_text(MKINITCPIO_CONF, updated)
            log(f"Registered hook 'acpi_t2_fix' in {MKINITCPIO_CONF}")

    def rebuild() -> None:
        run(["mkinitcpio", "-P"], echo_output=True)

    return [MKINITCPIO_HOOK_INSTALL, MKINITCPIO_CONF], apply, rebuild


DEPLOY_STRATEGY_FACTORY: dict[str, Callable[[], tuple[list[Path], Callable[[], None], Callable[[], None]]]] = {
    "dracut": dracut_strategy,
    "initramfs-tools": initramfs_tools_strategy,
    "mkinitcpio": mkinitcpio_strategy,
}


def deploy_tables(tables: Sequence[BuiltTable], timestamp: str, strategy: str) -> Path:
    backup_dir = BACKUP_ROOT / timestamp
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_dir.chmod(0o700)

    DEPLOY_DIR.mkdir(parents=True, exist_ok=True)
    DEPLOY_DIR.chmod(0o755)

    cpussdt = next((table for table in tables if table.kind == "CpuSSDT"), None)
    if cpussdt:
        check_cpussdt_duplicates(cpussdt.deploy_name)

    extra_tracked, apply_strategy, rebuild = DEPLOY_STRATEGY_FACTORY[strategy]()

    targets = [DEPLOY_DIR / table.deploy_name for table in tables]
    tracked = targets + extra_tracked
    existed_before = {path: path.exists() or path.is_symlink() for path in tracked}
    for path in tracked:
        backup_path(path, backup_dir)

    manifest = backup_dir / "MANIFEST.txt"
    manifest.write_text(
        f"ACPI T2 fix backup created before deployment (strategy: {strategy}).\n"
        + "\n".join(f"{path}: existed={existed_before[path]}" for path in tracked)
        + "\n",
        encoding="utf-8",
    )
    manifest.chmod(0o600)

    try:
        for table, target in zip(tables, targets):
            log(f"Deploying {table.kind}: {target}")
            atomic_copy(table.aml, target)

        apply_strategy()
        rebuild()
    except Exception as original_error:
        # Anything above failing -- including the initramfs rebuild itself --
        # means the machine could reboot into a half-updated, inconsistent
        # override set. Restore every tracked file to its pre-deployment
        # state (or delete it, if it didn't exist before) and rebuild the
        # initramfs again so a subsequent reboot behaves as if this run
        # never happened.
        log("Deployment failed; restoring backed-up files.")
        rollback_errors: list[str] = []
        for path in reversed(tracked):
            try:
                restore_file(path, backup_dir, existed_before[path])
            except Exception as rollback_error:  # noqa: BLE001 - preserve all rollback failures
                rollback_errors.append(f"{path}: {rollback_error}")
        try:
            rebuild()
        except Exception as rollback_rebuild_error:  # noqa: BLE001
            rollback_errors.append(f"initramfs rebuild after rollback: {rollback_rebuild_error}")

        detail = ""
        if rollback_errors:
            detail = "\nRollback also encountered:\n  - " + "\n  - ".join(rollback_errors)
        raise FixError(f"Deployment failed and rollback was attempted: {original_error}{detail}") from original_error

    return backup_dir


# ---------------------------------------------------------------------------
# Uninstall: remove any previously deployed table(s) and any of this
# script's own hook/config files, then rebuild the initramfs with whichever
# tool is currently installed. All three tools' hook files are checked for
# regardless of which one is currently detected, since the deploy method on
# a machine can change between install and uninstall (e.g. switching from
# dracut to mkinitcpio); only the initramfs *rebuild* step uses the
# currently detected strategy, since that is what actually runs at boot.
# ---------------------------------------------------------------------------


def find_deployed_tables() -> list[Path]:
    if not DEPLOY_DIR.is_dir():
        return []
    return sorted(p for p in DEPLOY_DIR.iterdir() if p.is_file() and p.suffix == ".aml")


def reverted_dracut_conf(existing: str) -> str | None:
    """Strip the lines dracut_strategy() adds. None means nothing is left
    worth keeping, so the caller should delete the file outright."""
    retained: list[str] = []
    setting_re = re.compile(r"^\s*(acpi_override|acpi_table_dir)\s*=")
    for line in existing.splitlines():
        if not setting_re.match(line):
            retained.append(line)
    while retained and not retained[-1].strip():
        retained.pop()
    return "\n".join(retained) + "\n" if retained else None


def remove_mkinitcpio_hook(text: str, hook_name: str) -> str:
    pattern = re.compile(r"^(?P<prefix>\s*HOOKS=\()(?P<body>[^)]*)(?P<suffix>\)\s*)$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return text
    hooks = [hook for hook in match.group("body").split() if hook != hook_name]
    replacement = match.group("prefix") + " ".join(hooks) + match.group("suffix")
    return text[: match.start()] + replacement + text[match.end() :]


def mkinitcpio_conf_needs_uninstall() -> bool:
    if not MKINITCPIO_CONF.is_file():
        return False
    text = MKINITCPIO_CONF.read_text(encoding="utf-8", errors="replace")
    return remove_mkinitcpio_hook(text, "acpi_t2_fix") != text


def find_uninstall_targets() -> tuple[list[Path], list[Path]]:
    """Return (tables, hook_files). MKINITCPIO_CONF is handled separately
    since, unlike the other targets, it is a pre-existing system file this
    script only ever edits in place, never deletes."""
    tables = find_deployed_tables()
    hook_files = [
        path
        for path in (DRACUT_CONF, INITRAMFS_TOOLS_HOOK, MKINITCPIO_HOOK_INSTALL)
        if path.exists() or path.is_symlink()
    ]
    return tables, hook_files


def uninstall_deployed(strategy: str) -> Path:
    """Back up, then remove every file this script may have deployed and
    reverse any hook/config edits, mirroring deploy_tables()'s
    backup-before-touching approach. Caller has already confirmed there is
    something to remove."""
    tables, hook_files = find_uninstall_targets()
    touch_mkinitcpio_conf = mkinitcpio_conf_needs_uninstall()

    timestamp = safe_timestamp()
    backup_dir = BACKUP_ROOT / f"{timestamp}-uninstall"
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_dir.chmod(0o700)

    tracked = tables + hook_files + ([MKINITCPIO_CONF] if touch_mkinitcpio_conf else [])
    for path in tracked:
        backup_path(path, backup_dir)

    manifest = backup_dir / "MANIFEST.txt"
    manifest.write_text(
        "ACPI T2 fix backup created before uninstall.\n"
        + "\n".join(f"{path}: removed" for path in tracked)
        + "\n",
        encoding="utf-8",
    )
    manifest.chmod(0o600)

    for table in tables:
        table.unlink()

    if DRACUT_CONF in hook_files:
        reverted = reverted_dracut_conf(DRACUT_CONF.read_text(encoding="utf-8", errors="replace"))
        if reverted is None:
            DRACUT_CONF.unlink()
        else:
            write_atomic_text(DRACUT_CONF, reverted)
    if INITRAMFS_TOOLS_HOOK in hook_files:
        INITRAMFS_TOOLS_HOOK.unlink()
    if MKINITCPIO_HOOK_INSTALL in hook_files:
        MKINITCPIO_HOOK_INSTALL.unlink()
    if touch_mkinitcpio_conf:
        conf_text = MKINITCPIO_CONF.read_text(encoding="utf-8", errors="replace")
        write_atomic_text(MKINITCPIO_CONF, remove_mkinitcpio_hook(conf_text, "acpi_t2_fix"))

    if strategy in DEPLOY_STRATEGY_FACTORY:
        _, _, rebuild = DEPLOY_STRATEGY_FACTORY[strategy]()
        rebuild()

    return backup_dir


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect and apply the documented CpuSSDT and DSDT fixes on T2 Macs running Linux, "
            "deriving model-specific CpuSSDT bits from the local firmware."
        )
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="detect, extract, patch, and validate, but do not deploy or rebuild initramfs",
    )
    parser.add_argument(
        "--reboot",
        action="store_true",
        help="reboot immediately after a successful initramfs rebuild",
    )
    parser.add_argument(
        "--workdir",
        help="use this new directory for extracted and compiled tables (must not already exist)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show every command run and its full output (including iasl remarks); "
        "off by default to keep normal runs quiet",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="remove any previously deployed T2 ACPI table override(s) and this "
        "script's own initramfs hook/config, then rebuild the initramfs "
        "(combine with --dry-run to only show what would be removed)",
    )
    return parser.parse_args(argv)


def print_banner(status: str, lines: Sequence[str] = ()) -> None:
    width = 70
    print("=" * width)
    print(f" RESULT: {status}")
    print("=" * width)
    for line in lines:
        print(f" {line}" if line else "")
    print("=" * width)


def manual_deploy_instructions(tables: Sequence[BuiltTable], os_release: dict[str, str]) -> list[str]:
    """Next steps when no supported initramfs tool was detected for automated
    deployment. See the module docstring for why NixOS and unrecognized
    setups end up here instead of being driven automatically."""
    lines = [
        "No supported initramfs tool (dracut, initramfs-tools, mkinitcpio) was",
        "detected, so the table(s) below were built and validated but NOT installed.",
        "",
        "Every one of these tools ultimately relies on the same generic kernel",
        "mechanism (CONFIG_ACPI_TABLE_UPGRADE, see Documentation/admin-guide/acpi/",
        "initrd_table_override.rst): the kernel loads any file placed at",
        "kernel/firmware/acpi/*.aml inside the initramfs. Deploy manually by getting",
        "these files into your initramfs at that path, then rebuild it and reboot:",
        "",
    ]
    for table in tables:
        lines.append(f"  {table.kind}: {table.aml} -> kernel/firmware/acpi/{table.deploy_name}")
    lines.append("")

    distro_id = os_release.get("ID", "").lower()
    if distro_id == "nixos":
        lines.extend(
            [
                "On NixOS, this is normally done declaratively, e.g. in configuration.nix:",
                '  boot.initrd.extraFiles."kernel/firmware/acpi/dsdt.aml".source = <path above>;',
                "then: sudo nixos-rebuild switch",
                "(double-check this option against search.nixos.org -- it has not been",
                "verified against a live NixOS system).",
            ]
        )
    else:
        lines.extend(
            [
                "If you use genkernel or booster, check their documentation for the",
                "equivalent 'add an extra file to the initramfs' mechanism.",
            ]
        )
    return lines


def run_uninstall(strategy: str, os_release: dict[str, str], args: argparse.Namespace) -> int:
    tables, hook_files = find_uninstall_targets()
    touch_mkinitcpio_conf = mkinitcpio_conf_needs_uninstall()
    tracked = tables + hook_files + ([MKINITCPIO_CONF] if touch_mkinitcpio_conf else [])

    if not tracked:
        print_banner(
            "NOTHING TO DO",
            ["No previously deployed T2 ACPI files or hooks were found; nothing to uninstall."],
        )
        return 0

    if args.dry_run:
        print_banner(
            "DRY RUN OK",
            ["Would remove or revert:"]
            + [f"  {path}" for path in tracked]
            + ["", "Nothing was changed; re-run without --dry-run to uninstall."],
        )
        return 0

    required: list[str] = []
    if strategy != "manual":
        required.append(DEPLOY_STRATEGY_COMMAND[strategy])
    if args.reboot:
        required.append(reboot_command()[0])
    require_commands(required, os_release)

    backup_dir = uninstall_deployed(strategy)
    summary = ", ".join(str(path) for path in tracked)

    if strategy == "manual":
        print_banner(
            "UNINSTALLED - MANUAL INITRAMFS REBUILD NEEDED",
            [
                f"Removed: {summary}",
                f"Backup:  {backup_dir}",
                "",
                "No supported initramfs tool was detected, so rebuild your initramfs",
                "manually with your distro's normal tool so the removal takes effect.",
            ],
        )
        return 0

    if args.reboot:
        print_banner(
            "UNINSTALLED - REBOOTING",
            [
                f"Removed: {summary}",
                f"Backup:  {backup_dir}",
                "",
                "Rebooting now because --reboot was supplied.",
            ],
        )
        os.sync()
        run(reboot_command())
    else:
        print_banner(
            "UNINSTALLED",
            [
                f"Removed: {summary}",
                f"Backup:  {backup_dir}",
                "",
                f"Reboot for the removal to take effect: sudo {' '.join(reboot_command())}",
            ],
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.dry_run and args.reboot:
        raise FixError("--dry-run and --reboot cannot be used together.")
    if args.uninstall and args.workdir:
        raise FixError("--uninstall does not use --workdir.")

    global VERBOSE
    VERBOSE = args.debug

    require_root()
    product_name, os_release = require_apple_intel_supported()

    strategy = detect_deploy_strategy(os_release)
    log(f"Detected model: {product_name} (deploy method: {strategy})")

    if args.uninstall:
        return run_uninstall(strategy, os_release, args)

    detection = detect_problems()
    log(
        "Detection: "
        f"CpuSSDT={'affected' if detection.cpussdt_problem else 'not detected'}, "
        f"DSDT={'affected' if detection.dsdt_problem else 'not detected'}"
    )

    if not detection.cpussdt_problem and not detection.dsdt_problem:
        print_banner(
            "NOTHING TO DO",
            [
                "Neither documented ACPI bug was found in this boot's kernel log.",
                "Nothing was changed; there is nothing further to do.",
            ],
        )
        return 0

    required: list[str] = []
    if detection.cpussdt_problem or detection.dsdt_problem:
        required.append("iasl")
    if not args.dry_run and strategy != "manual":
        required.append(DEPLOY_STRATEGY_COMMAND[strategy])
    if args.reboot:
        required.append(reboot_command()[0])
    require_commands(required, os_release)

    timestamp = safe_timestamp()
    workdir = make_workdir(args.workdir, timestamp)
    log(f"Working directory: {workdir}")

    tables: list[BuiltTable] = []
    if detection.cpussdt_problem:
        tables.append(build_cpussdt(workdir, product_name))
    if detection.dsdt_problem:
        tables.append(build_dsdt(workdir))

    kinds = ", ".join(table.kind for table in tables)
    log("All requested tables were patched and validated successfully.")

    if args.dry_run:
        print_banner(
            "DRY RUN OK",
            [
                f"Built and validated: {kinds}",
                "Nothing was deployed; no files were changed; initramfs was not rebuilt.",
                "Re-run without --dry-run to deploy.",
            ],
        )
        return 0

    if strategy == "manual":
        print_banner("BUILT - MANUAL DEPLOY NEEDED", manual_deploy_instructions(tables, os_release))
        return 0

    backup_dir = deploy_tables(tables, timestamp, strategy)

    if args.reboot:
        print_banner(
            "SUCCESS - REBOOTING",
            [
                f"Deployed: {kinds}",
                f"Backup:   {backup_dir}",
                "",
                "Rebooting now because --reboot was supplied.",
            ],
        )
        os.sync()
        run(reboot_command())
    else:
        print_banner(
            "SUCCESS",
            [
                f"Deployed: {kinds}",
                f"Backup:   {backup_dir}",
                "",
                "Next steps:",
                f"  1. Reboot for the fix to take effect: sudo {' '.join(reboot_command())}",
                "  2. After rebooting, confirm the error is gone:",
                "     journalctl -b0 -k --grep=AE_AML_BUFFER_LIMIT",
                "     (or: dmesg | grep AE_AML_BUFFER_LIMIT, if you have no systemd journal)",
            ],
        )

    return 0


def print_failure_banner(message: str) -> None:
    print("=" * 70, file=sys.stderr)
    print(" RESULT: FAILED", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"[acpi-fix] ERROR: {message}", file=sys.stderr)
    if not VERBOSE:
        print("[acpi-fix] Re-run with --debug for full command output.", file=sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FixError as exc:
        print_failure_banner(str(exc))
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\n[acpi-fix] Interrupted; no further actions taken.", file=sys.stderr)
        raise SystemExit(130)
    except OSError as exc:
        print_failure_banner(f"operating-system error: {exc}")
        raise SystemExit(1)
