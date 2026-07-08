# T2 Mac ACPI Fixes for Linux

`t2_acpi_fix.py` automates two well-known ACPI fixes for Intel T2 Macs
running Linux:

- **SMPBOOT resume delay**: CPUs take 10-17+ seconds to come back online
  after S3 sleep.
- **DSDT `_OSC` buffer overflow**: every boot logs `AE_AML_BUFFER_LIMIT`,
  and Linux never negotiates PCIe capabilities such as hotplug, AER, LTR,
  and DPC.

The script is built with safety as the top priority. It only deploys a
patched table once every verification step has passed (a clean `iasl`
recompile for CpuSSDT, an independent re-disassembly check for DSDT),
backs up every file it is about to touch before touching it, and
automatically rolls back if a deployment step fails partway through. The
"Why run this instead of patching by hand" section below explains this in
more detail.

Both bugs and their fixes were originally documented as a manual
disassemble, edit, and recompile walkthrough by
[deqrocks/t2-acpi-fixes](https://github.com/deqrocks/t2-acpi-fixes). This
repo turns that exact walkthrough into a single script. It applies the
same fixes and the same underlying ASL changes, but detects, patches,
independently verifies, and deploys them automatically instead of by
hand. If you want to understand or perform every step yourself, that repo
is still the best reference.

---

## Why run this instead of patching by hand

- **Built fresh from your own machine, every run.** The patched tables
  embed machine-specific data (physical memory addresses, per-model
  sub-table layouts), so a `.aml` built on someone else's Mac is not safe
  to reuse on yours even if it's the "same" model. The script always
  reads `/sys/firmware/acpi/tables` on the machine it's running on.
- **Only patches what's actually broken.** It checks the current boot's
  kernel log first and only touches CpuSSDT and/or DSDT if that boot
  actually shows the corresponding error.
- **Independently re-checks its own patch.** The DSDT is patched directly
  in AML bytes rather than recompiled, because a full recompile is
  unreliable across real Apple DSDTs (see the script's module docstring
  for why). The result is then re-disassembled with `iasl` as a second,
  independent check before anything is deployed.
- **Backs up before touching anything**, and rolls back automatically if
  a deployment step fails partway through.

---

## Requirements

- An Intel T2 Mac (Apple silicon Macs are unaffected; this does nothing
  on non-Apple hardware).
- Linux, booted normally (not a live/rescue environment).
- Python 3.10+ and `iasl` (`acpica-tools` or `acpica`, depending on
  distro; the script tells you the right package name if it's missing).
- Root.

## Quick start

```sh
sudo ./t2_acpi_fix.py
```

That's it for the default case: it detects which of the two bugs affect
this boot, patches only those tables, verifies the patch, deploys it, and
tells you to reboot.

```
--dry-run     detect, build and validate, but don't deploy or touch the initramfs
--reboot      reboot automatically once deployment succeeds
--debug       show every command run and its full output (iasl remarks included);
              off by default to keep normal runs quiet
--workdir DIR use this directory for extracted/compiled tables instead of a
              fresh one under /var/tmp (must not already exist)
--uninstall   remove any previously deployed table(s) and this script's own
              initramfs hook/config, then rebuild the initramfs
```

Run with `--dry-run` first if you just want to see what it would do.

## What it does, step by step

1. Confirms this is an Intel Apple machine and reads the current boot's
   kernel log (the systemd journal, or `dmesg` if there is no systemd
   journal) for the two documented error signatures.
2. **CpuSSDT**, if affected: disassembles it, derives the `\SDTL` bitmask
   from the sub-tables Linux has *actually* already loaded on this
   machine (not a hard-coded value), patches the ASL source, and requires
   a clean recompile (0 errors, 0 warnings).
3. **DSDT**, if affected: locates every `_OSC` method matching one of the
   two documented broken AML shapes and replaces just that method's bytes
   with the fixed version, byte-for-byte, preserving the table's overall
   size and every enclosing package length. Then independently
   re-disassembles both the original and the patched table with `iasl`
   and confirms the diagnostics didn't get worse and the fix is actually
   present in the decompiled output.
4. Bumps the OEM revision and recomputes the checksum on each patched
   table.
5. Backs up every file about to be touched under
   `/var/backups/acpi-t2-fix/<timestamp>/`.
6. Deploys the table(s) to `/usr/local/lib/firmware/acpi/` and wires them
   into the initramfs using whichever tool is actually installed (see
   below), then rebuilds it. Any failure here triggers an automatic
   rollback to the pre-deployment state.
7. Prints a summary banner with the backup location and the exact
   commands to reboot and verify the fix afterwards.

Nothing reboots on its own unless you pass `--reboot`.

## Supported distros / deployment methods

The script doesn't guess from the distro name. It looks for whichever
initramfs tool is actually installed:

| Tool detected | Typical distro | Status |
|---|---|---|
| `dracut` | Fedora (default); Arch/Manjaro/EndeavourOS if dracut is installed | Confirmed working on real hardware |
| `update-initramfs` | Debian, Ubuntu | Implemented, not yet confirmed on real hardware |
| `mkinitcpio` | Arch, Manjaro, EndeavourOS (default) | Implemented, not yet confirmed on real hardware |
| none of the above | NixOS, Gentoo (OpenRC/genkernel/booster), anything unrecognized | Not automated. Tables are still built and validated, and the script prints manual next steps |

NixOS is always treated as manual-only, even if one of the above tools
happens to be present: NixOS's initrd is rebuilt declaratively from
`configuration.nix`, so files written under `/etc` here would just be
discarded on the next `nixos-rebuild switch`.

If you run this on Debian/Ubuntu or Arch/Manjaro/EndeavourOS-with-mkinitcpio,
**please open an issue with the outcome either way** (worked or didn't).
Those paths follow each tool's documented hook mechanism but haven't been
exercised on a real T2 Mac yet.

## Verifying and reverting

After rebooting, confirm the fix took effect:

```sh
journalctl -b0 -k --grep=AE_AML_BUFFER_LIMIT   # DSDT fix: should be empty
journalctl -b0 -k --grep='Marking method'      # CpuSSDT fix: should be empty
```

(substitute `dmesg | grep ...` if you have no systemd journal)

To revert, run `sudo ./t2_acpi_fix.py --uninstall`. It removes the deployed
table(s), undoes the initramfs hook or config it added, rebuilds the
initramfs, and backs up everything it touches first, the same way a normal
run does. Use `--uninstall --dry-run` first to see exactly what it would
remove without changing anything. Alternatively, you can revert by hand:
restore the files listed in
`/var/backups/acpi-t2-fix/<timestamp>/MANIFEST.txt` to their original
locations (that directory contains a full copy of every file the script
changed, from right before it changed it), then rebuild the initramfs
with your distro's normal tool and reboot.

---

## Contributing model coverage

The two documented `_OSC` AML shapes are currently confirmed on:

- **Inline-UUID shape**: MacBookAir9,1, MacBookPro16,2
- **Named-UUID / PCI-hotplug shape**: MacBookPro15,1, MacBookPro16,1, Macmini8,1

If the script fails to recognize your DSDT's `_OSC` method(s), or you hit
any other error, please open an issue with:

- your model (`cat /sys/class/dmi/id/product_name`),
- your distro (`cat /etc/os-release`),
- the full script output, ideally re-run with `--debug`.

Since every run's output is machine-specific, there's no expectation to
share `.aml` files for others to reuse directly. What's useful is the log
output and, if you're comfortable sharing it, the `*.patch-report.txt`
and `.dsl` disassembly from the working directory the script printed, so
a new AML shape can get added to the script itself.
