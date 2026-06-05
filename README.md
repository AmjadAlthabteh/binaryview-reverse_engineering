# BinView — PE Analyzer & Import Reconstructor

A modern **C++23** static analysis tool for Windows PE binaries. Parses executables and DLLs from scratch — no third-party PE libraries — and produces a rich terminal report with entropy analysis, import reconstruction, disassembly, and JSON export.

![C++23](https://img.shields.io/badge/C%2B%2B-23-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

| Feature | Details |
|---|---|
| **PE parsing** | DOS header, NT headers, section table, imports, exports, relocations — 32-bit and 64-bit |
| **Import table** | All DLLs and functions with hints, ordinals, and IAT slot VAs |
| **Export table** | Function RVAs, ordinals, forwarder chains |
| **Entropy analysis** | Per-section Shannon entropy with packing detection |
| **Malware triage** | 10+ automated indicators: high entropy, known packer names, entry-point anomalies, suspicious APIs |
| **Memory map** | Visual section layout bar chart scaled to image size |
| **Disassembly** | Entry-point disassembly via [Capstone](https://www.capstone-engine.org/) |
| **JSON export** | Full structured report — suitable for piping into toolchains |
| **Terminal UI** | ANSI colour output with box-drawing layout |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  BinView ─ PE Analyzer & Import Reconstructor                    v1.0  ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ PE HEADERS ─────────────────────────────────────────────────────────────────┐
│  File:                   C:\Windows\System32\notepad.exe
│  Machine:                AMD64 (x64)
│  Subsystem:              Windows GUI
│  Entry Point:            0x000017a0  [.text]
│  Image Base:             0x0000000140000000
│  Timestamp:              2022-11-05 10:23:41 UTC
└──────────────────────────────────────────────────────────────────────────────┘

┌─ MEMORY MAP ─────────────────────────────────────────────────────────────────┐
│  0x140001000  .text    96K   ████████████████████████████████████  R-X  6.42
│  0x14001a000  .rdata   36K   ██████████████                        R--  5.89
│  0x140023000  .data     4K   ██                                    RW-  2.34
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Building

### Requirements

- **Visual Studio 2022** (17.7 or later — required for `std::expected`)
- **vcpkg** with `VCPKG_ROOT` set
- **CMake** 3.25+

### Steps

```powershell
# 1. Configure (vcpkg installs dependencies automatically)
cmake --preset default

# 2. Build
cmake --build --preset default

# 3. Run
.\build\Release\binview.exe <path-to-exe>
```

Dependencies are declared in `vcpkg.json` and installed automatically:

| Library | Purpose |
|---|---|
| [Capstone](https://github.com/capstone-engine/capstone) | x86/x64 disassembly |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON report export |
| [Catch2](https://github.com/catchorg/Catch2) | Unit testing |

---

## Usage

```
binview.exe <PE-file> [options]

Options:
  -d, --disasm        Show entry-point disassembly
  -i, --iat           Show reconstructed Import Address Table
  -r, --relocs        Show relocation table summary
  -v, --verbose       Print all imported/exported function names
  -j, --json <file>   Write JSON report to file
      --json-stdout   Print JSON to stdout
  -h, --help          Show this help
```

### Examples

```powershell
# Quick overview
binview.exe C:\Windows\System32\notepad.exe

# Full analysis with disassembly and verbose imports
binview.exe malware_sample.exe --disasm --verbose

# Export JSON for further processing
binview.exe target.dll --json report.json

# Pipe JSON into jq
binview.exe target.exe --json-stdout | jq '.analysis'
```

---

## Architecture

```
src/
├── core/
│   ├── pe_types.hpp        — PE data structures, Result<T>, PEInfo root type
│   ├── file_mapper.hpp     — RAII memory-mapped file (Win32 CreateFileMapping)
│   └── pe_parser.hpp       — Full 32/64-bit parser
├── analysis/
│   ├── entropy.hpp         — Shannon entropy, 5-level classification
│   ├── triage.hpp          — Packing/malware heuristics
│   └── iat_reconstructor.hpp — Flat IAT view sorted by slot VA
├── disasm/
│   └── disassembler.hpp    — Capstone RAII wrapper
├── viz/
│   ├── tui.hpp             — ANSI terminal UI components
│   └── memory_map.hpp      — Section bar chart renderer
└── export/
    └── json_exporter.hpp   — nlohmann/json serialisation
```

All analysis modules are **header-only**. The only translation unit is `src/main.cpp`.

---

## Running Tests

```powershell
cmake --preset default
cmake --build --preset default
ctest --preset default
```

---

## Design Notes

- **Zero exceptions** — all errors propagate through `Result<T>` = `std::expected<T, std::string>`
- **RAII throughout** — Win32 `HANDLE` wrapped with a custom deleter using `using pointer = HANDLE`; Capstone handle and instruction arrays have dedicated RAII guards
- **No raw `new`/`delete`** — `std::vector`, `std::optional`, `std::unique_ptr` everywhere
- **`std::span<const std::byte>`** for all zero-copy memory views into the mapped file
- **`std::filesystem::path`** for all file I/O

---

## Stretch Goals (Planned)

- [ ] Pattern / YARA-style signature scanning
- [ ] Live process memory inspection via `ReadProcessMemory`
- [ ] DLL dependency graph (DOT format)
- [ ] Overlay / certificate section detection
- [ ] PE checksum verification

---

## License

MIT
