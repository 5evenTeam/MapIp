# MapIp installer and packaging

This directory holds the Windows packaging layer for MapIp: a maintainer build
script, an Inno Setup script and an end-user install script. The point of all of
it is that after installing, you open any terminal, type `mapip`, and the
terminal UI starts.

| File | Purpose |
|------|---------|
| `build.ps1` | Maintainer build: `mapip.exe`, checksums, Inno Setup installer. |
| `mapip.iss` | Inno Setup 6 script for the per-machine installer. |
| `install.ps1` | End-user installer: a single binary in `%LOCALAPPDATA%`, user `PATH`, shortcuts, uninstaller. |
| `uninstall.ps1` | Not stored here; `install.ps1` writes it into the install prefix. |

MapIp is one static Go binary, so packaging is small: there is no runtime, no
virtual environment and no native engines to vendor.

## Toolchain

| Tool | Version used |
|------|--------------|
| Go | 1.24+ (`go`) |
| Inno Setup | 6 (`iscc`) |

`iscc` is resolved from `PATH`, then from `%ProgramFiles(x86)%\Inno Setup 6`,
`%ProgramFiles%\Inno Setup 6` and the scoop shim.

## Maintainer build

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\build.ps1
```

Parameters:

- `-Version <x.y.z>` - version stamped into messages and the checksum file.
  Default `0.5.0`. The script warns if `cmd\mapip\main.go` declares a different
  `const version`.
- `-SkipBuild` - reuse an existing `dist\mapip.exe`.
- `-SkipInstaller` - do not run `iscc`.

Steps and outputs:

1. `go build -trimpath -ldflags "-s -w" -o dist\mapip.exe ./cmd/mapip` from the
   repository root.
2. `dist\mapip.exe` is copied over the tracked `mapip.exe` at the repository
   root, and `SHA256SUMS.txt` is rewritten for it.
3. `iscc installer\mapip.iss` produces `dist\MapIp-Setup-0.5.0.exe`.
4. An artifact list with sizes and SHA-256 hashes is printed.

The script exits non-zero when a real step fails.

The version and installer filename are also written into `mapip.iss`
(`AppVersion`, `OutputBaseFilename`) and into the `-Version` default of
`build.ps1`; update all three together when bumping the release.

## Inno Setup package (`mapip.iss`)

Packages `dist\mapip.exe` into `{autopf}\MapIp` (`Program Files\MapIp` for an
administrative install).

- Adds `{app}` to the machine `PATH`
  (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`) when the
  `path` task is selected. `ChangesEnvironment=yes` makes Inno notify running
  applications, and the uninstaller removes exactly the entry it added, leaving
  the rest of `PATH` alone.
- Start Menu shortcut `MapIp` -> `mapip.exe`; optional desktop shortcut via the
  `desktopicon` task.
- `[Run]` offers to launch `mapip.exe` when the installer finishes, which opens
  the terminal UI.
- Uninstall removes the shortcuts, the `PATH` entry and the application
  directory, and appears in Add/Remove Programs.
- Requires administrator rights because it writes the machine `PATH`.

Because `PATH` changes reach new processes only, a terminal that was already
open when you installed will not see `mapip` until it is restarted.

## End-user install (`install.ps1`)

For machines without administrator rights or without Inno Setup:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\install.ps1
```

Parameters:

- `-Prefix <dir>` - install location. Default:
  `%LOCALAPPDATA%\Programs\MapIp`.
- `-Source <path>` - use an existing `mapip.exe`.
- `-Build` - build `mapip.exe` with the Go toolchain instead of copying one.
- `-NoPath` - do not touch the user `PATH`.
- `-NoShortcuts` - do not create shortcuts.
- `-Uninstall` - remove the installation.
- `-Quiet` - less output.

Without `-Source`, the script uses `dist\mapip.exe` or `mapip.exe` from the
repository root, and falls back to `go build` when neither exists and Go is on
`PATH`. It always installs to the user scope: `%LOCALAPPDATA%` plus the user
`PATH`, so no elevation is required.

Uninstall:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\install.ps1 -Uninstall
```

Pass the same `-Prefix` that was used at install time. `-Uninstall` runs the
generated `<Prefix>\uninstall.ps1`, which removes the shortcuts, the user
`PATH` entry and the install directory.

## Bare `mapip` opens the TUI

`cmd\mapip\main.go` starts the terminal UI when `mapip` is run with no
arguments and both stdin and stdout are terminals. In a non-interactive
context (a pipe, a service, a script) it prints the usage summary instead, so
it never blocks waiting for a terminal that is not there. Every explicit
subcommand still works as before, and `mapip scan` is still the scanning entry
point.

## Validation

PowerShell syntax check (does not run the scripts):

```powershell
powershell -NoProfile -Command "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('installer\install.ps1',[ref]$null,[ref]$e); if($e){$e; exit 1} else {'OK'}"
powershell -NoProfile -Command "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('installer\build.ps1',[ref]$null,[ref]$e); if($e){$e; exit 1} else {'OK'}"
```

Confirm the Inno Setup compiler is available (do not compile until
`dist\mapip.exe` exists):

```powershell
iscc /?
```
