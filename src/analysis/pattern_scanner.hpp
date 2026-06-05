#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binview {

// ── Pattern representation ────────────────────────────────────────────────────

// One token in a pattern: either a fixed byte or a wildcard (?? / ?).
struct PatternByte {
    uint8_t value{};
    bool    wildcard{};

    [[nodiscard]] bool matches(uint8_t byte) const noexcept {
        return wildcard || byte == value;
    }
};

// A compiled pattern ready for scanning.
struct Pattern {
    std::string              name;
    std::vector<PatternByte> bytes;

    [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
    [[nodiscard]] size_t size() const noexcept { return bytes.size(); }
};

// ── Match result ──────────────────────────────────────────────────────────────

struct PatternMatch {
    std::string section_name;
    uint64_t    va{};          // virtual address of the first matched byte
    FileOffset  file_offset{}; // corresponding file offset
    std::string pattern_name;
};

// ── Parser ────────────────────────────────────────────────────────────────────

// Parse a hex string pattern with optional wildcards.
// Format: "48 89 5C 24 ?? 48 8B F9" — space-separated hex bytes or ?? wildcards.
// Returns std::nullopt if the pattern string is malformed.
[[nodiscard]] inline std::optional<Pattern>
parse_pattern(std::string_view text, std::string_view name = "") {
    Pattern pat;
    pat.name = std::string{name};

    size_t i = 0;
    while (i < text.size()) {
        // skip whitespace
        while (i < text.size() && text[i] == ' ') ++i;
        if (i >= text.size()) break;

        // wildcard: ?? or ?
        if (text[i] == '?') {
            pat.bytes.push_back({0, true});
            ++i;
            if (i < text.size() && text[i] == '?') ++i;
            continue;
        }

        // hex byte
        if (i + 1 >= text.size()) return std::nullopt;
        uint8_t val{};
        auto    res = std::from_chars(&text[i], &text[i + 2], val, 16);
        if (res.ec != std::errc{}) return std::nullopt;
        pat.bytes.push_back({val, false});
        i += 2;
    }

    return pat.empty() ? std::nullopt : std::optional{std::move(pat)};
}

// ── Scanner ───────────────────────────────────────────────────────────────────

class PatternScanner {
public:
    // Scan every section for all patterns. Returns all matches.
    [[nodiscard]] static std::vector<PatternMatch>
    scan(const PEInfo& info, const FileMapper& mapper,
         std::span<const Pattern> patterns) {

        std::vector<PatternMatch> results;
        auto file_view = mapper.view();

        for (const auto& sec : info.sections) {
            if (sec.raw_offset == 0 || sec.raw_size == 0) continue;
            if (sec.raw_offset >= file_view.size()) continue;

            size_t avail = std::min<size_t>(sec.raw_size,
                                            file_view.size() - sec.raw_offset);
            auto sec_data = file_view.subspan(sec.raw_offset, avail);

            for (const auto& pat : patterns) {
                scan_section(results, sec, sec_data, pat, info.image_base);
            }
        }

        // Sort by VA for deterministic output
        std::ranges::sort(results, {}, &PatternMatch::va);
        return results;
    }

    // Convenience: scan a single pattern by text.
    [[nodiscard]] static std::vector<PatternMatch>
    scan_one(const PEInfo& info, const FileMapper& mapper,
             std::string_view pattern_text, std::string_view name = "") {
        auto pat = parse_pattern(pattern_text, name);
        if (!pat) return {};
        std::array<Pattern, 1> arr{std::move(*pat)};
        return scan(info, mapper, arr);
    }

    // Built-in signatures for common constructs.
    [[nodiscard]] static std::vector<Pattern> common_signatures() {
        std::vector<Pattern> sigs;

        // x64 function prologue: push rbp / mov rbp, rsp
        if (auto p = parse_pattern("55 48 89 E5", "x64-prologue-rbp"))
            sigs.push_back(std::move(*p));

        // x64 function prologue: sub rsp, N (common MSVC style)
        if (auto p = parse_pattern("48 83 EC ?? 48 8B", "x64-prologue-sub-rsp"))
            sigs.push_back(std::move(*p));

        // CALL followed by POP (classic position-independent shellcode)
        if (auto p = parse_pattern("E8 00 00 00 00 58", "shellcode-call-pop"))
            sigs.push_back(std::move(*p));

        // XOR reg, reg (register zeroing — common in shellcode)
        if (auto p = parse_pattern("31 C0", "xor-eax-eax"))
            sigs.push_back(std::move(*p));

        // MZ header embedded in section (dropped PE)
        if (auto p = parse_pattern("4D 5A 90 00", "embedded-MZ-header"))
            sigs.push_back(std::move(*p));

        // GetProcAddress shellcode fingerprint
        if (auto p = parse_pattern("FF D0 ?? ?? 85 C0", "call-reg-check-null"))
            sigs.push_back(std::move(*p));

        return sigs;
    }

private:
    static void scan_section(std::vector<PatternMatch>& results,
                             const SectionInfo& sec,
                             std::span<const std::byte> data,
                             const Pattern& pat,
                             uint64_t image_base) {
        if (pat.size() > data.size()) return;

        size_t limit = data.size() - pat.size() + 1;
        for (size_t offset = 0; offset < limit; ++offset) {
            bool found = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (!pat.bytes[j].matches(static_cast<uint8_t>(data[offset + j]))) {
                    found = false;
                    break;
                }
            }
            if (found) {
                PatternMatch m;
                m.section_name = sec.name;
                m.va           = image_base + sec.virtual_address + offset;
                m.file_offset  = sec.raw_offset + static_cast<FileOffset>(offset);
                m.pattern_name = pat.name;
                results.push_back(std::move(m));
            }
        }
    }
};

} // namespace binview
