#pragma once

#include "core/pe_types.hpp"
#include "analysis/entropy.hpp"
#include "viz/tui.hpp"

#include <algorithm>
#include <cstdio>
#include <format>
#include <string>

namespace binview::tui {

inline void print_memory_map(const PEInfo& info) {
    if (info.sections.empty()) return;

    box_top("MEMORY MAP");

    constexpr int BAR_MAX = 38;  // visual columns for the bar

    // Scale bars relative to the largest section
    uint32_t max_size = 1;
    for (const auto& sec : info.sections)
        max_size = std::max(max_size, sec.effective_size());

    // Column header
    std::printf("%s│%s  %-20s  %-9s  %-7s  %-*s  Perms  Entropy\n",
                col::DGRAY.data(), col::RESET.data(),
                "Virtual Address", "Section", "Size",
                BAR_MAX, "Layout");

    std::printf("%s│%s  %-20s  %-9s  %-7s  %-*s  -----  -------\n",
                col::DGRAY.data(), col::RESET.data(),
                "────────────────────",
                "─────────", "───────",
                BAR_MAX, std::string(BAR_MAX, '─').c_str());

    for (const auto& sec : info.sections) {
        uint32_t sz  = sec.effective_size();
        int bar_len  = static_cast<int>(
            (static_cast<double>(sz) / static_cast<double>(max_size)) * BAR_MAX);
        if (bar_len < 1 && sz > 0) bar_len = 1;

        // Color by section type
        const char* bar_col =
            sec.is_executable() ? col::YELLOW.data()  :
            sec.is_writable()   ? col::DRED.data()    :
                                  col::DGREEN.data();

        // Build bar (█ is 3 bytes in UTF-8 but 1 visual column)
        std::string bar;
        bar.reserve(static_cast<size_t>(bar_len) * 3);
        for (int i = 0; i < bar_len; ++i) bar += "\xe2\x96\x88"; // U+2588 FULL BLOCK

        // Trailing spaces to fill the column visually
        int pad = BAR_MAX - bar_len;
        std::string padding(pad, ' ');

        // Human-readable size
        std::string size_str;
        if (sz >= 1024 * 1024)
            size_str = std::format("{:.1f}M", sz / (1024.0 * 1024.0));
        else if (sz >= 1024)
            size_str = std::format("{:.0f}K", sz / 1024.0);
        else
            size_str = std::format("{}B", sz);

        uint64_t va = info.image_base + sec.virtual_address;

        auto elevel = EntropyAnalyzer::classify(sec.entropy);
        auto ecol   = EntropyAnalyzer::level_color(elevel);

        std::printf("%s│%s  %s0x%016llx%s  %s%-9s%s  %s%7s%s  %s%s%s%s  %s%s%s  %s%.2f%s\n",
                    col::DGRAY.data(), col::RESET.data(),
                    col::BLUE.data(), (unsigned long long)va, col::RESET.data(),
                    bar_col, sec.name.c_str(), col::RESET.data(),
                    col::DGRAY.data(), size_str.c_str(), col::RESET.data(),
                    bar_col, bar.c_str(), col::RESET.data(), padding.c_str(),
                    col::DCYAN.data(), sec.permissions().c_str(), col::RESET.data(),
                    ecol.data(), sec.entropy, col::RESET.data());
    }

    blank_row();

    std::printf("%s│%s  Legend: %s\xe2\x96\x88\xe2\x96\x88%s Executable  "
                "%s\xe2\x96\x88\xe2\x96\x88%s Writable  "
                "%s\xe2\x96\x88\xe2\x96\x88%s Read-only\n",
                col::DGRAY.data(), col::RESET.data(),
                col::YELLOW.data(), col::RESET.data(),
                col::DRED.data(),   col::RESET.data(),
                col::DGREEN.data(), col::RESET.data());

    box_bottom();
    std::printf("\n");
}

} // namespace binview::tui
