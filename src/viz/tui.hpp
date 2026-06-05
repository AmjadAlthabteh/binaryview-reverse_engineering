#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "core/pe_types.hpp"
#include "analysis/entropy.hpp"
#include "analysis/overlay.hpp"
#include "analysis/pattern_scanner.hpp"
#include "analysis/string_extractor.hpp"

#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binview::tui {

// ── ANSI colour constants ─────────────────────────────────────────────────────

namespace col {
    constexpr std::string_view RESET   = "\033[0m";
    constexpr std::string_view BOLD    = "\033[1m";
    constexpr std::string_view DIM     = "\033[2m";
    constexpr std::string_view RED     = "\033[1;31m";
    constexpr std::string_view GREEN   = "\033[1;32m";
    constexpr std::string_view YELLOW  = "\033[1;33m";
    constexpr std::string_view BLUE    = "\033[1;34m";
    constexpr std::string_view MAGENTA = "\033[1;35m";
    constexpr std::string_view CYAN    = "\033[1;36m";
    constexpr std::string_view WHITE   = "\033[1;37m";
    constexpr std::string_view DGRAY   = "\033[0;90m";
    constexpr std::string_view DRED    = "\033[0;31m";
    constexpr std::string_view DGREEN  = "\033[0;32m";
    constexpr std::string_view DYELLOW = "\033[0;33m";
    constexpr std::string_view DCYAN   = "\033[0;36m";
}

// Enable VT processing and UTF-8 output on Windows.
inline void init_console() {
    SetConsoleOutputCP(CP_UTF8);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(out, &mode);
    SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// ── Box-drawing helpers ───────────────────────────────────────────────────────

constexpr int BOX_WIDTH = 80;

inline void box_top(std::string_view title = {}) {
    if (title.empty()) {
        std::printf("\033[0;90m┌%s┐\033[0m\n",
                    std::string(BOX_WIDTH - 2, '─').c_str());
        return;
    }
    std::string line = std::format("─ {}{}{} ", col::CYAN, title, col::DGRAY);
    int fill = BOX_WIDTH - 4 - static_cast<int>(title.size());
    if (fill < 0) fill = 0;
    std::printf("%s┌%s%s┐%s\n",
                col::DGRAY.data(), line.c_str(),
                std::string(fill, '─').c_str(), col::RESET.data());
}

inline void box_bottom() {
    std::printf("%s└%s┘%s\n",
                col::DGRAY.data(),
                std::string(BOX_WIDTH - 2, '─').c_str(),
                col::RESET.data());
}

inline void box_row(std::string_view content) {
    // content is printed verbatim between │ chars; caller handles padding
    std::printf("%s│%s %s\n", col::DGRAY.data(), col::RESET.data(),
                std::string{content}.c_str());
}

// A labelled key/value row with padding to fit BOX_WIDTH.
inline void kv_row(std::string_view key, std::string_view value,
                   std::string_view value_color = col::WHITE) {
    std::string line =
        std::format("  {}{:<22}{} {}{}{}", col::DCYAN, key, col::RESET,
                    value_color, value, col::RESET);
    std::printf("%s│%s%s\n", col::DGRAY.data(), col::RESET.data(), line.c_str());
}

inline void blank_row() {
    std::printf("%s│%s\n", col::DGRAY.data(), col::RESET.data());
}

inline void separator() {
    std::printf("%s├%s┤%s\n", col::DGRAY.data(),
                std::string(BOX_WIDTH - 2, '─').c_str(), col::RESET.data());
}

// ── Banner ────────────────────────────────────────────────────────────────────

inline void print_banner() {
    std::printf("\n%s", col::CYAN.data());
    std::printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    std::printf("║  %sBinView%s %s─ PE Analyzer & Import Reconstructor%s                 %sv1.0%s  ║\n",
                col::WHITE.data(), col::CYAN.data(),
                col::DGRAY.data(), col::CYAN.data(),
                col::DYELLOW.data(), col::CYAN.data());
    std::printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    std::printf("%s\n", col::RESET.data());
}

// ── PE headers panel ─────────────────────────────────────────────────────────

inline void print_headers(const PEInfo& info) {
    box_top("PE HEADERS");

    kv_row("File:",       info.file_path);
    kv_row("Size:",       std::format("{:,} bytes ({} KB)",
                                      info.file_size, info.file_size / 1024));
    blank_row();

    kv_row("Machine:",    info.machine_name(), col::YELLOW);
    kv_row("Subsystem:",  info.subsystem_name());
    kv_row("Type:",       info.is_dll ? "DLL" : "Executable");
    kv_row("Bitness:",    info.is_64bit ? "64-bit" : "32-bit", col::CYAN);
    blank_row();

    kv_row("Image Base:", std::format("{:#018x}", info.image_base), col::BLUE);
    kv_row("Entry Point:", std::format("{:#010x}  [{}]",
                                       info.entry_point, info.entry_section), col::BLUE);
    kv_row("Image Size:", std::format("{:#x} ({} KB)",
                                      info.image_size, info.image_size / 1024));

    // Decode timestamp
    if (info.timestamp) {
        time_t ts = static_cast<time_t>(info.timestamp);
        char   buf[64]{};
        struct tm tm_val{};
        gmtime_s(&tm_val, &ts);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_val);
        kv_row("Timestamp:", buf, col::DYELLOW);
    } else {
        kv_row("Timestamp:", "Not set / stripped", col::DRED);
    }

    kv_row("Linker:", std::format("{}.{}", info.major_linker_version,
                                   info.minor_linker_version));

    box_bottom();
    std::printf("\n");
}

// ── Sections panel ───────────────────────────────────────────────────────────

inline void print_sections(const PEInfo& info) {
    box_top(std::format("SECTIONS ({})", info.sections.size()));

    // Header row
    std::printf("%s│%s  %s%-10s  %-12s %-12s %-10s  %s%s\n",
                col::DGRAY.data(), col::RESET.data(),
                col::DGRAY.data(),
                "Name", "VirtAddr", "VirtSize", "RawSize",
                "Perms   Entropy", col::RESET.data());

    std::printf("%s│  %s%-10s  %-12s %-12s %-10s  %s%s\n",
                col::DGRAY.data(),
                col::DGRAY.data(),
                "──────────", "────────────", "────────────", "──────────",
                "─────  ────────", col::RESET.data());

    for (const auto& sec : info.sections) {
        auto lvl   = EntropyAnalyzer::classify(sec.entropy);
        auto ecol  = EntropyAnalyzer::level_color(lvl);

        std::string name_colored =
            std::format("{}{}{}",
                        sec.is_executable() ? col::YELLOW.data() :
                        sec.is_writable()   ? col::DRED.data()   :
                                              col::DGREEN.data(),
                        sec.name, col::RESET.data());

        std::printf("%s│%s  %-22s  %s%#010x%s  %s%#010x%s  %s%#010x%s  %s%s%s  %s%.2f%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    name_colored.c_str(),
                    col::BLUE.data(), sec.virtual_address, col::RESET.data(),
                    col::DGRAY.data(), sec.virtual_size,   col::RESET.data(),
                    col::DGRAY.data(), sec.raw_size,       col::RESET.data(),
                    col::DCYAN.data(), sec.permissions().c_str(), col::RESET.data(),
                    ecol.data(), sec.entropy, col::RESET.data());
    }

    box_bottom();
    std::printf("\n");
}

// ── Imports panel ────────────────────────────────────────────────────────────

inline void print_imports(const PEInfo& info, bool verbose = false) {
    int total = info.total_imported_functions();
    box_top(std::format("IMPORTS ({} DLLs, {} functions)",
                        info.imports.size(), total));

    if (info.imports.empty()) {
        std::printf("%s│%s  %sNo imports found.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DRED.data(), col::RESET.data());
        box_bottom();
        std::printf("\n");
        return;
    }

    for (const auto& dll : info.imports) {
        std::printf("%s│%s  %s%s%s  %s(%zu functions)%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::YELLOW.data(), dll.name.c_str(), col::RESET.data(),
                    col::DGRAY.data(), dll.functions.size(), col::RESET.data());

        if (verbose) {
            for (const auto& fn : dll.functions) {
                if (fn.by_ordinal) {
                    std::printf("%s│%s    %s%-6u%s  %sOrdinal%s\n",
                                col::DGRAY.data(), col::RESET.data(),
                                col::DGRAY.data(), fn.ordinal, col::RESET.data(),
                                col::DRED.data(), col::RESET.data());
                } else {
                    std::printf("%s│%s    %s[h=%04X]%s  %s\n",
                                col::DGRAY.data(), col::RESET.data(),
                                col::DGRAY.data(), fn.hint, col::RESET.data(),
                                fn.name.c_str());
                }
            }
        }
    }

    box_bottom();
    std::printf("\n");
}

// ── Exports panel ────────────────────────────────────────────────────────────

inline void print_exports(const PEInfo& info, bool verbose = false) {
    if (!info.exports) {
        box_top("EXPORTS");
        std::printf("%s│%s  %sNo export directory.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DGRAY.data(), col::RESET.data());
        box_bottom();
        std::printf("\n");
        return;
    }

    const auto& exp = *info.exports;
    box_top(std::format("EXPORTS — {} ({} functions)",
                        exp.dll_name, exp.functions.size()));

    kv_row("Ordinal Base:", std::to_string(exp.ordinal_base));
    blank_row();

    if (verbose) {
        for (const auto& fn : exp.functions) {
            if (fn.forwarded) {
                std::printf("%s│%s  %s[%04X]%s  %-40s  %s→ %s%s\n",
                            col::DGRAY.data(), col::RESET.data(),
                            col::DGRAY.data(), fn.ordinal, col::RESET.data(),
                            fn.name.c_str(),
                            col::DYELLOW.data(), fn.forwarder_string.c_str(),
                            col::RESET.data());
            } else {
                std::printf("%s│%s  %s[%04X]%s  %-40s  %s%#010x%s\n",
                            col::DGRAY.data(), col::RESET.data(),
                            col::DGRAY.data(), fn.ordinal, col::RESET.data(),
                            fn.name.c_str(),
                            col::BLUE.data(), fn.function_rva, col::RESET.data());
            }
        }
    }

    box_bottom();
    std::printf("\n");
}

// ── Triage / analysis panel ───────────────────────────────────────────────────

inline void print_triage(const PEInfo& info) {
    const auto& a = info.analysis;

    std::string_view verdict_col = a.possibly_packed ? col::RED : col::GREEN;
    std::string_view verdict_str = a.possibly_packed
        ? "SUSPICIOUS — possible packing or obfuscation"
        : "Clean — no automated triage flags";

    box_top("TRIAGE ANALYSIS");

    kv_row("Overall Entropy:", std::format("{:.3f} / 8.000", a.overall_entropy),
           EntropyAnalyzer::level_color(
               EntropyAnalyzer::classify(a.overall_entropy)));
    kv_row("Verdict:", verdict_str, verdict_col);
    blank_row();

    if (a.indicators.empty()) {
        std::printf("%s│%s  %sNo indicators found.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DGREEN.data(), col::RESET.data());
    } else {
        for (const auto& ind : a.indicators) {
            std::string_view c = ind.find("[ENTROPY]") != std::string::npos ||
                                  ind.find("[PACKER]")  != std::string::npos
                                  ? col::RED : col::DYELLOW;
            std::printf("%s│%s  %s•%s %s\n",
                        col::DGRAY.data(), col::RESET.data(),
                        c.data(), col::RESET.data(), ind.c_str());
        }
    }

    box_bottom();
    std::printf("\n");
}

// ── Disassembly panel ─────────────────────────────────────────────────────────

inline void print_disasm(const std::vector<Instruction>& insns,
                         std::string_view section_name) {
    box_top(std::format("DISASSEMBLY — {} ({} instructions)",
                        section_name, insns.size()));

    for (const auto& ins : insns) {
        // Print raw bytes
        std::string raw_bytes;
        for (uint8_t b : ins.bytes)
            raw_bytes += std::format("{:02x} ", b);
        while (raw_bytes.size() < 24) raw_bytes += ' ';

        std::printf("%s│%s  %s%#018x%s  %s%-24s%s  %s%-8s%s  %s%s%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::BLUE.data(), ins.address, col::RESET.data(),
                    col::DGRAY.data(), raw_bytes.c_str(), col::RESET.data(),
                    col::YELLOW.data(), ins.mnemonic.c_str(), col::RESET.data(),
                    col::WHITE.data(), ins.op_str.c_str(), col::RESET.data());
    }

    box_bottom();
    std::printf("\n");
}

// ── Relocations summary ───────────────────────────────────────────────────────

inline void print_relocations(const PEInfo& info) {
    box_top(std::format("RELOCATIONS ({} entries)", info.relocations.size()));
    if (info.relocations.empty()) {
        std::printf("%s│%s  %sNo relocation table.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DGRAY.data(), col::RESET.data());
    } else {
        // Count by type
        std::unordered_map<uint16_t, int> type_count;
        for (const auto& r : info.relocations) ++type_count[r.type];
        for (const auto& [type, count] : type_count) {
            RelocationEntry dummy{0, type, 0};
            std::printf("%s│%s  %s%-10s%s  %s%d entries%s\n",
                        col::DGRAY.data(), col::RESET.data(),
                        col::CYAN.data(), dummy.type_name().data(), col::RESET.data(),
                        col::DGRAY.data(), count, col::RESET.data());
        }
    }
    box_bottom();
    std::printf("\n");
}

// ── Overlay panel ─────────────────────────────────────────────────────────────

inline void print_overlay(const std::optional<OverlayInfo>& ov) {
    box_top("OVERLAY DETECTION");

    if (!ov) {
        std::printf("%s│%s  %sNo overlay detected.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DGREEN.data(), col::RESET.data());
        box_bottom();
        std::printf("\n");
        return;
    }

    auto elevel = EntropyAnalyzer::classify(ov->entropy);
    auto ecol   = EntropyAnalyzer::level_color(elevel);

    kv_row("Offset:",      std::format("{:#x}", ov->offset), col::BLUE);
    kv_row("Size:",        std::format("{:,} bytes ({:.1f} KB)",
                                       ov->size, ov->size / 1024.0));
    kv_row("Magic:",       ov->magic_string(), col::DYELLOW);
    kv_row("Fingerprint:", ov->fingerprint(), col::YELLOW);
    kv_row("Entropy:",     std::format("{:.3f} — {}",
                                       ov->entropy,
                                       EntropyAnalyzer::level_label(elevel)),
           ecol);

    box_bottom();
    std::printf("\n");
}

// ── Pattern scan panel ────────────────────────────────────────────────────────

inline void print_pattern_scan(const std::vector<PatternMatch>& matches,
                                bool no_results_ok = false) {
    box_top(std::format("PATTERN SCAN ({} match{})",
                        matches.size(), matches.size() == 1 ? "" : "es"));

    if (matches.empty()) {
        std::printf("%s│%s  %s%s%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    no_results_ok ? col::DGREEN.data() : col::DGRAY.data(),
                    no_results_ok ? "No signatures matched."
                                  : "No common signatures matched.",
                    col::RESET.data());
        box_bottom();
        std::printf("\n");
        return;
    }

    // Header
    std::printf("%s│%s  %s%-20s  %-9s  %-20s  %s%s\n",
                col::DGRAY.data(), col::RESET.data(),
                col::DGRAY.data(),
                "Virtual Address", "Section", "Pattern",
                "File Offset", col::RESET.data());

    for (const auto& m : matches) {
        std::printf("%s│%s  %s0x%016llx%s  %s%-9s%s  %s%-20s%s  %s0x%08x%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::BLUE.data(),    (unsigned long long)m.va, col::RESET.data(),
                    col::YELLOW.data(),  m.section_name.c_str(),  col::RESET.data(),
                    col::CYAN.data(),    m.pattern_name.c_str(),  col::RESET.data(),
                    col::DGRAY.data(),   m.file_offset,           col::RESET.data());
    }

    box_bottom();
    std::printf("\n");
}

// ── Strings panel ─────────────────────────────────────────────────────────────

inline void print_strings(const std::vector<ExtractedString>& strings) {
    size_t interesting = 0;
    for (const auto& s : strings)
        if (s.is_interesting()) ++interesting;

    box_top(std::format("STRINGS ({} interesting / {} total)",
                        interesting, strings.size()));

    if (strings.empty()) {
        std::printf("%s│%s  %sNo interesting strings found.%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::DGRAY.data(), col::RESET.data());
        box_bottom();
        std::printf("\n");
        return;
    }

    // Column header
    std::printf("%s│%s  %s%-10s  %-9s  W  %-20s  %s%s\n",
                col::DGRAY.data(), col::RESET.data(),
                col::DGRAY.data(),
                "Kind", "Section", "VA", "Value",
                col::RESET.data());

    for (const auto& s : strings) {
        const char* kcol =
            s.kind == StringKind::Suspicious   ? col::RED.data()     :
            s.kind == StringKind::URL          ? col::CYAN.data()    :
            s.kind == StringKind::IPv4         ? col::YELLOW.data()  :
            s.kind == StringKind::FilePath     ? col::DYELLOW.data() :
            s.kind == StringKind::RegistryKey  ? col::MAGENTA.data() :
            s.kind == StringKind::Email        ? col::DGREEN.data()  :
                                                 col::DGRAY.data();

        std::string label{s.kind_label()};
        if (label.empty()) label = "str";

        // Truncate long values for display
        std::string display = s.value;
        if (display.size() > 60) {
            display.resize(57);
            display += "...";
        }

        std::printf("%s│%s  %s%-10s%s  %s%-9s%s  %s%s  %s%#018llx%s  %s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    kcol,             label.c_str(),         col::RESET.data(),
                    col::DGRAY.data(), s.section_name.c_str(), col::RESET.data(),
                    col::DGRAY.data(), s.wide ? "W" : " ",
                    col::BLUE.data(),  (unsigned long long)s.va, col::RESET.data(),
                    display.c_str());
    }

    box_bottom();
    std::printf("\n");
}

} // namespace binview::tui
