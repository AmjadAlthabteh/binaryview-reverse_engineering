#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binview {

// ── String classification ─────────────────────────────────────────────────────

enum class StringKind {
    Plain,       // generic printable string
    URL,         // http/https/ftp scheme
    IPv4,        // dotted-quad address
    FilePath,    // C:\..., %SystemRoot%\..., UNC \\...
    RegistryKey, // HKEY_... / HKLM\... / HKCU\...
    Email,       // contains @
    Suspicious,  // cmd, powershell, WScript, base64 blob, etc.
};

struct ExtractedString {
    std::string  value;
    StringKind   kind{StringKind::Plain};
    bool         wide{};         // true = UTF-16LE source
    std::string  section_name;
    FileOffset   file_offset{};
    uint64_t     va{};

    [[nodiscard]] std::string_view kind_label() const noexcept {
        switch (kind) {
            case StringKind::URL:         return "URL";
            case StringKind::IPv4:        return "IPv4";
            case StringKind::FilePath:    return "PATH";
            case StringKind::RegistryKey: return "REG";
            case StringKind::Email:       return "EMAIL";
            case StringKind::Suspicious:  return "SUSPICIOUS";
            default:                      return "";
        }
    }

    [[nodiscard]] bool is_interesting() const noexcept {
        return kind != StringKind::Plain;
    }
};

// ── Classifier ────────────────────────────────────────────────────────────────

namespace detail {

[[nodiscard]] inline bool starts_with_icase(std::string_view s,
                                             std::string_view prefix) noexcept {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i]))) return false;
    return true;
}

[[nodiscard]] inline bool contains_icase(std::string_view hay,
                                          std::string_view needle) noexcept {
    if (needle.size() > hay.size()) return false;
    for (size_t i = 0; i <= hay.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

[[nodiscard]] inline bool looks_like_ipv4(std::string_view s) noexcept {
    // Quick heuristic: N.N.N.N where each N is 1–3 digits
    int dots = 0, digits = 0;
    for (char c : s) {
        if (c == '.') {
            if (digits == 0 || digits > 3) return false;
            ++dots;
            digits = 0;
        } else if (c >= '0' && c <= '9') {
            ++digits;
        } else {
            return false;
        }
    }
    return dots == 3 && digits > 0 && digits <= 3;
}

[[nodiscard]] inline StringKind classify(std::string_view s) noexcept {
    // URL schemes
    if (starts_with_icase(s, "http://")  ||
        starts_with_icase(s, "https://") ||
        starts_with_icase(s, "ftp://")   ||
        starts_with_icase(s, "ftps://"))
        return StringKind::URL;

    // Registry keys
    if (starts_with_icase(s, "HKEY_")   ||
        starts_with_icase(s, "HKLM\\")  ||
        starts_with_icase(s, "HKCU\\")  ||
        starts_with_icase(s, "HKCR\\")  ||
        starts_with_icase(s, "HKU\\")   ||
        starts_with_icase(s, "Software\\") ||
        starts_with_icase(s, "SYSTEM\\CurrentControlSet"))
        return StringKind::RegistryKey;

    // File paths
    if (starts_with_icase(s, "C:\\")       ||
        starts_with_icase(s, "D:\\")       ||
        starts_with_icase(s, "\\\\")       ||   // UNC
        starts_with_icase(s, "%SystemRoot%") ||
        starts_with_icase(s, "%APPDATA%")   ||
        starts_with_icase(s, "%TEMP%")      ||
        starts_with_icase(s, "%WINDIR%"))
        return StringKind::FilePath;

    // IPv4
    if (looks_like_ipv4(s))
        return StringKind::IPv4;

    // Email (simple heuristic: one @ with chars around it)
    {
        auto at = s.find('@');
        if (at != std::string_view::npos && at > 0 && at + 1 < s.size())
            return StringKind::Email;
    }

    // Suspicious keywords
    static constexpr std::array suspicious_kw = {
        std::string_view{"cmd.exe"},
        std::string_view{"powershell"},
        std::string_view{"wscript"},
        std::string_view{"cscript"},
        std::string_view{"mshta"},
        std::string_view{"regsvr32"},
        std::string_view{"rundll32"},
        std::string_view{"net user"},
        std::string_view{"net localgroup"},
        std::string_view{"SeDebugPrivilege"},
        std::string_view{"CreateRemoteThread"},
        std::string_view{"VirtualAllocEx"},
        std::string_view{"WriteProcessMemory"},
        std::string_view{"ShellExecute"},
        std::string_view{"WinExec"},
        std::string_view{"URLDownloadToFile"},
        std::string_view{"InternetOpenUrl"},
    };
    for (const auto& kw : suspicious_kw)
        if (contains_icase(s, kw))
            return StringKind::Suspicious;

    return StringKind::Plain;
}

} // namespace detail

// ── Extractor ─────────────────────────────────────────────────────────────────

class StringExtractor {
public:
    struct Config {
        size_t min_length    = 5;    // minimum string character count
        bool   include_wide  = true; // scan for UTF-16LE strings
        bool   all_strings   = false;// false = only interesting strings + min_length filter
    };

    [[nodiscard]] static std::vector<ExtractedString>
    extract(const PEInfo& info, const FileMapper& mapper,
            const Config& cfg = {}) {

        std::vector<ExtractedString> results;
        auto file_view = mapper.view();

        for (const auto& sec : info.sections) {
            if (sec.raw_offset == 0 || sec.raw_size == 0) continue;
            if (sec.raw_offset >= file_view.size()) continue;

            size_t avail = std::min<size_t>(sec.raw_size,
                                            file_view.size() - sec.raw_offset);
            auto data = file_view.subspan(sec.raw_offset, avail);

            extract_ascii(results, data, sec, info.image_base, cfg);
            if (cfg.include_wide)
                extract_wide(results, data, sec, info.image_base, cfg);
        }

        // Stable sort: interesting first, then by VA
        std::stable_sort(results.begin(), results.end(),
            [](const ExtractedString& a, const ExtractedString& b) {
                if (a.is_interesting() != b.is_interesting())
                    return a.is_interesting() > b.is_interesting();
                return a.va < b.va;
            });

        return results;
    }

private:
    static bool is_printable(char c) noexcept {
        return c >= 0x20 && c < 0x7F;
    }

    static void extract_ascii(std::vector<ExtractedString>& out,
                               std::span<const std::byte> data,
                               const SectionInfo& sec,
                               uint64_t image_base,
                               const Config& cfg) {
        size_t i = 0;
        while (i < data.size()) {
            char c = static_cast<char>(data[i]);
            if (!is_printable(c)) { ++i; continue; }

            size_t start = i;
            std::string s;
            while (i < data.size()) {
                char ch = static_cast<char>(data[i]);
                if (!is_printable(ch)) break;
                s += ch;
                ++i;
            }

            if (s.size() < cfg.min_length) continue;

            auto kind = detail::classify(s);
            if (!cfg.all_strings && kind == StringKind::Plain) continue;

            ExtractedString es;
            es.value        = std::move(s);
            es.kind         = kind;
            es.wide         = false;
            es.section_name = sec.name;
            es.file_offset  = sec.raw_offset + static_cast<FileOffset>(start);
            es.va           = image_base + sec.virtual_address + start;
            out.push_back(std::move(es));
        }
    }

    static void extract_wide(std::vector<ExtractedString>& out,
                              std::span<const std::byte> data,
                              const SectionInfo& sec,
                              uint64_t image_base,
                              const Config& cfg) {
        // UTF-16LE: every other byte is 0x00 for ASCII range
        if (data.size() < 4) return;

        size_t i = 0;
        while (i + 1 < data.size()) {
            uint8_t lo = static_cast<uint8_t>(data[i]);
            uint8_t hi = static_cast<uint8_t>(data[i + 1]);

            if (!is_printable(static_cast<char>(lo)) || hi != 0x00) {
                ++i;
                continue;
            }

            size_t start = i;
            std::string s;
            while (i + 1 < data.size()) {
                uint8_t l = static_cast<uint8_t>(data[i]);
                uint8_t h = static_cast<uint8_t>(data[i + 1]);
                if (!is_printable(static_cast<char>(l)) || h != 0x00) break;
                s += static_cast<char>(l);
                i += 2;
            }

            if (s.size() < cfg.min_length) continue;

            auto kind = detail::classify(s);
            if (!cfg.all_strings && kind == StringKind::Plain) continue;

            ExtractedString es;
            es.value        = std::move(s);
            es.kind         = kind;
            es.wide         = true;
            es.section_name = sec.name;
            es.file_offset  = sec.raw_offset + static_cast<FileOffset>(start);
            es.va           = image_base + sec.virtual_address + start;
            out.push_back(std::move(es));
        }
    }
};

} // namespace binview
