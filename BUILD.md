# Building BinView

## Prerequisites

| Requirement | Version |
|---|---|
| Visual Studio 2022 | 17.7+ (for `std::expected`) |
| vcpkg | latest |
| CMake | 3.25+ |

## Quick Start

```powershell
# 1. Set VCPKG_ROOT (add to your profile for permanence)
$env:VCPKG_ROOT = "C:\vcpkg"   # adjust to your vcpkg install

# 2. Configure (installs capstone, nlohmann-json, catch2 automatically)
cmake --preset default

# 3. Build
cmake --build --preset default

# 4. Run (binary ends up in build\Release\)
.\build\Release\binview.exe C:\Windows\System32\notepad.exe
```

## Build Options

```powershell
# Debug build
cmake --preset debug
cmake --build --preset debug

# Ninja (faster incremental, requires Ninja installed)
cmake --preset ninja
cmake --build build-ninja
```

## Run Tests

```powershell
cmake --preset default
cmake --build --preset default
ctest --preset default
```

## Usage Examples

```
# Basic analysis
binview.exe target.exe

# Full analysis with disassembly and verbose imports
binview.exe target.exe --disasm --verbose

# Export JSON report
binview.exe target.exe --json report.json

# Show IAT reconstruction
binview.exe target.exe --iat

# Everything at once
binview.exe target.exe -d -i -r -v --json out.json
```

## Options

| Flag | Description |
|---|---|
| `-d`, `--disasm` | Disassemble entry-point section (Capstone) |
| `-i`, `--iat` | Show reconstructed Import Address Table |
| `-r`, `--relocs` | Show relocation table summary |
| `-v`, `--verbose` | Print all function names in imports/exports |
| `-j FILE`, `--json FILE` | Write full JSON report to FILE |
| `--json-stdout` | Print JSON to stdout |
| `-h`, `--help` | Show help |
