#pragma once

#include "core/pe_types.hpp"
#include "analysis/entropy.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <string_view>

namespace binview {

// Populates info.analysis.indicators and info.analysis.possibly_packed.
// Call after EntropyAnalyzer::annotate().
class TriageAnalyzer {
public:
    static void run(PEInfo& info) {
        check_section_entropy(info);
        check_section_names(info);
        check_entry_point(info);
        check_imports(info);
        check_permissions(info);
        check_timestamp(info);
        check_size_anomalies(info);
    }

private:
    static void push(PEInfo& info, std::string msg) {
        info.analysis.indicators.push_back(std::move(msg));
    }

    // ── Entropy ───────────────────────────────────────────────────────────────

    static void check_section_entropy(PEInfo& info) {
        for (const auto& sec : info.sections) {
            auto lvl = EntropyAnalyzer::classify(sec.entropy);
            if (lvl == EntropyAnalyzer::Level::VeryHigh) {
                push(info, std::format(
                    "[ENTROPY] Section '{}' entropy={:.2f} — likely compressed/encrypted",
                    sec.name, sec.entropy));
                info.analysis.possibly_packed = true;
            }
        }
    }

    // ── Known packer section names ────────────────────────────────────────────

    static void check_section_names(PEInfo& info) {
        static constexpr std::array known_packers = {
            std::string_view{"UPX0"},  std::string_view{"UPX1"},
            std::string_view{"UPX2"},  std::string_view{".nsp0"},
            std::string_view{".nsp1"}, std::string_view{".petite"},
            std::string_view{".aspack"},std::string_view{".adata"},
            std::string_view{"MPRESS1"},std::string_view{"MPRESS2"},
            std::string_view{".packed"},std::string_view{"_winzip_"},
            std::string_view{"PELOCKnt"},
        };
        for (const auto& sec : info.sections) {
            for (const auto& known : known_packers) {
                if (sec.name == known) {
                    push(info, std::format(
                        "[PACKER] Known packer section: '{}' ({})",
                        sec.name, known));
                    info.analysis.possibly_packed = true;
                }
            }
        }
    }

    // ── Entry point location ──────────────────────────────────────────────────

    static void check_entry_point(PEInfo& info) {
        if (info.entry_point == 0) return;

        if (!info.entry_section.empty() && info.entry_section != ".text") {
            push(info, std::format(
                "[EP] Entry point in '{}' (not .text) — common in packed binaries",
                info.entry_section));
        }

        // Check if entry falls in a writable section
        if (const auto* sec = info.section_for_rva(info.entry_point)) {
            if (sec->is_writable()) {
                push(info, std::format(
                    "[EP] Entry point is in a writable section '{}'", sec->name));
            }
        }
    }

    // ── Import table analysis ─────────────────────────────────────────────────

    static void check_imports(PEInfo& info) {
        if (info.imports.empty()) {
            push(info, "[IMPORT] No import table — possibly packed or manually mapped");
            info.analysis.possibly_packed = true;
            return;
        }

        int total = info.total_imported_functions();
        if (total < 5) {
            push(info, std::format(
                "[IMPORT] Only {} imported function(s) — stub-loader pattern", total));
            info.analysis.possibly_packed = true;
        }

        // Suspicious API names indicative of injection / code manipulation
        static constexpr std::array watchlist = {
            std::string_view{"VirtualAlloc"},
            std::string_view{"VirtualProtect"},
            std::string_view{"WriteProcessMemory"},
            std::string_view{"ReadProcessMemory"},
            std::string_view{"CreateRemoteThread"},
            std::string_view{"NtUnmapViewOfSection"},
            std::string_view{"ZwUnmapViewOfSection"},
            std::string_view{"SetThreadContext"},
            std::string_view{"ResumeThread"},
            std::string_view{"IsDebuggerPresent"},
            std::string_view{"CheckRemoteDebuggerPresent"},
            std::string_view{"OutputDebugString"},
        };

        for (const auto& dll : info.imports) {
            for (const auto& fn : dll.functions) {
                for (const auto& w : watchlist) {
                    if (fn.name.find(w) != std::string::npos) {
                        push(info, std::format(
                            "[API] Suspicious import: {}!{}", dll.name, fn.name));
                    }
                }
            }
        }
    }

    // ── Section permission anomalies ──────────────────────────────────────────

    static void check_permissions(PEInfo& info) {
        for (const auto& sec : info.sections) {
            if (sec.is_readable() && sec.is_writable() && sec.is_executable()) {
                push(info, std::format(
                    "[PERM] Section '{}' is RWX — atypical, may stage shellcode",
                    sec.name));
            }
        }
    }

    // ── Timestamp ─────────────────────────────────────────────────────────────

    static void check_timestamp(PEInfo& info) {
        if (info.timestamp == 0)
            push(info, "[TS] Zero timestamp — may have been stripped or tampered");
        else if (info.timestamp == 0xFFFF'FFFF)
            push(info, "[TS] Timestamp 0xFFFFFFFF — reproducible/deterministic build or tampered");
    }

    // ── Size anomalies ────────────────────────────────────────────────────────

    static void check_size_anomalies(PEInfo& info) {
        for (const auto& sec : info.sections) {
            // Virtual size >> raw size is common in packers (tiny stub, large BSS)
            if (sec.raw_size > 0 && sec.virtual_size > sec.raw_size * 10) {
                push(info, std::format(
                    "[SIZE] Section '{}': VirtualSize ({}) >> RawSize ({}) by 10×",
                    sec.name, sec.virtual_size, sec.raw_size));
            }
        }
    }
};

} // namespace binview
