#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <array>
#include <cmath>
#include <span>

namespace binview {

class EntropyAnalyzer {
public:
    // Shannon entropy in bits per byte [0.0 – 8.0].
    [[nodiscard]] static double calculate(std::span<const std::byte> data) noexcept {
        if (data.empty()) return 0.0;

        std::array<uint64_t, 256> freq{};
        for (const auto b : data)
            ++freq[static_cast<uint8_t>(b)];

        const double inv = 1.0 / static_cast<double>(data.size());
        double       h   = 0.0;
        for (const auto c : freq) {
            if (c == 0) continue;
            const double p = static_cast<double>(c) * inv;
            h -= p * std::log2(p);
        }
        return h;
    }

    // Annotate each section with its entropy and compute the overall average.
    static void annotate(PEInfo& info, const FileMapper& mapper) noexcept {
        const auto file_view = mapper.view();
        double total = 0.0;
        int    count = 0;

        for (auto& sec : info.sections) {
            if (sec.raw_offset == 0 || sec.raw_size == 0 ||
                sec.raw_offset >= file_view.size()) {
                sec.entropy = 0.0;
                continue;
            }
            size_t len = std::min<size_t>(sec.raw_size,
                                          file_view.size() - sec.raw_offset);
            sec.entropy = calculate(file_view.subspan(sec.raw_offset, len));
            total += sec.entropy;
            ++count;
        }

        info.analysis.overall_entropy = count > 0 ? total / count : 0.0;
    }

    // ── Entropy classification ────────────────────────────────────────────────

    enum class Level { VeryLow, Low, Normal, High, VeryHigh };

    [[nodiscard]] static Level classify(double e) noexcept {
        if (e < 2.0) return Level::VeryLow;
        if (e < 4.0) return Level::Low;
        if (e < 6.5) return Level::Normal;
        if (e < 7.2) return Level::High;
        return Level::VeryHigh;
    }

    [[nodiscard]] static std::string_view level_label(Level l) noexcept {
        switch (l) {
            case Level::VeryLow:  return "Very Low";
            case Level::Low:      return "Low";
            case Level::Normal:   return "Normal";
            case Level::High:     return "High";
            case Level::VeryHigh: return "Very High";
        }
        return "?";
    }

    // ANSI colour code for the entropy bar in the TUI
    [[nodiscard]] static std::string_view level_color(Level l) noexcept {
        switch (l) {
            case Level::VeryLow:  return "\033[0;34m";   // dim blue
            case Level::Low:      return "\033[0;32m";   // green
            case Level::Normal:   return "\033[0;36m";   // cyan
            case Level::High:     return "\033[0;33m";   // yellow
            case Level::VeryHigh: return "\033[1;31m";   // bright red
        }
        return "\033[0m";
    }
};

} // namespace binview
