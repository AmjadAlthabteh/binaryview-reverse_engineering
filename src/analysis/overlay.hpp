#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"
#include "analysis/entropy.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace binview {

// Data appended to a PE past its last section's raw data.
// Common in: self-extracting archives, some packers, embedded payloads,
// digital signature blobs, and update containers.
struct OverlayInfo {
    FileOffset offset{};    // file offset where overlay begins
    uint64_t   size{};      // number of overlay bytes
    double     entropy{};   // Shannon entropy of overlay data

    // Quick fingerprint: first 4 bytes (magic detection)
    uint8_t magic[4]{};

    [[nodiscard]] std::string magic_string() const {
        return std::format("{:02X} {:02X} {:02X} {:02X}",
                           magic[0], magic[1], magic[2], magic[3]);
    }

    // Heuristic: what does the overlay look like?
    [[nodiscard]] std::string fingerprint() const {
        // PE / MZ
        if (magic[0] == 'M' && magic[1] == 'Z') return "MZ (embedded PE)";
        // ZIP local file header
        if (magic[0] == 'P' && magic[1] == 'K' &&
            magic[2] == 0x03 && magic[3] == 0x04) return "ZIP archive";
        // 7-zip
        if (magic[0] == '7' && magic[1] == 'z' &&
            magic[2] == 0xBC && magic[3] == 0xAF) return "7-Zip archive";
        // RAR4
        if (magic[0] == 'R' && magic[1] == 'a' &&
            magic[2] == 'r' && magic[3] == '!') return "RAR archive";
        // PDF
        if (magic[0] == '%' && magic[1] == 'P' &&
            magic[2] == 'D' && magic[3] == 'F') return "PDF document";
        // Windows Authenticode (PKCS#7 DER)
        if (magic[0] == 0x30 && magic[1] == 0x82) return "Authenticode signature (PKCS#7)";

        auto lvl = EntropyAnalyzer::classify(entropy);
        if (lvl == EntropyAnalyzer::Level::VeryHigh) return "High-entropy blob (possibly encrypted/compressed)";
        if (lvl == EntropyAnalyzer::Level::VeryLow)  return "Low-entropy data (padding or mostly-zero)";
        return "Unknown";
    }
};

class OverlayDetector {
public:
    // Returns OverlayInfo if the file has data beyond all section raw data,
    // otherwise returns std::nullopt.
    [[nodiscard]] static std::optional<OverlayInfo>
    detect(const PEInfo& info, const FileMapper& mapper) {
        if (info.sections.empty()) return std::nullopt;

        // The overlay starts after the highest raw-data end address
        FileOffset end_of_sections = 0;
        for (const auto& sec : info.sections) {
            if (sec.raw_size == 0) continue;
            FileOffset sec_end = sec.raw_offset + sec.raw_size;
            end_of_sections = std::max(end_of_sections, sec_end);
        }

        if (end_of_sections == 0) return std::nullopt;

        uint64_t file_size = mapper.size();
        if (file_size <= end_of_sections) return std::nullopt;

        uint64_t overlay_size = file_size - end_of_sections;

        // Ignore tiny tails (alignment padding < 512 bytes)
        if (overlay_size < 512) return std::nullopt;

        OverlayInfo ov;
        ov.offset = end_of_sections;
        ov.size   = overlay_size;

        auto file_view = mapper.view();
        auto overlay_data = file_view.subspan(end_of_sections,
                                              static_cast<size_t>(overlay_size));

        ov.entropy = EntropyAnalyzer::calculate(overlay_data);

        // Read magic bytes
        for (int i = 0; i < 4 && i < static_cast<int>(overlay_data.size()); ++i)
            ov.magic[i] = static_cast<uint8_t>(overlay_data[i]);

        return ov;
    }
};

} // namespace binview
