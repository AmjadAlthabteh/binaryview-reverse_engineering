#pragma once

// The Rich header is an undocumented structure inserted by the MSVC linker
// between the DOS stub and the PE signature. It records every compiler and
// tool that contributed object files to the binary — a toolchain fingerprint
// usable for attribution and provenance analysis.
//
// Layout (on disk, every DWORD XOR'd with the checksum key):
//   "DanS"           — 4-byte marker (0x536E6144)
//   padding[3]       — three zero DWORDs
//   N × (compid, count) pairs
//   "Rich"           — end marker (0x68636952), stored in plain text
//   key              — XOR key (= checksum), stored in plain text

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binview {

// ── One compiler/tool entry ───────────────────────────────────────────────────

struct RichRecord {
    uint16_t product_id{};    // identifies the tool (compiler, linker, masm…)
    uint16_t build_number{};  // specific build of that tool
    uint32_t use_count{};     // number of .obj files stamped with this entry
};

// ── Parsed Rich header ────────────────────────────────────────────────────────

struct RichHeader {
    uint32_t               xor_key{};         // stored checksum/key
    bool                   checksum_valid{};  // computed checksum == stored key
    std::vector<RichRecord> records;
};

// ── Parser ────────────────────────────────────────────────────────────────────

class RichHeaderParser {
public:
    // Returns std::nullopt when no Rich header is present (e.g. non-MSVC or stripped).
    [[nodiscard]] static std::optional<RichHeader>
    parse(const FileMapper& mapper, uint32_t pe_offset) {
        // The Rich header lives in [0x40, pe_offset). Need at least 16 bytes.
        if (pe_offset < 0x40 + 16) return std::nullopt;
        if (pe_offset > mapper.size()) return std::nullopt;

        const auto* base = reinterpret_cast<const uint32_t*>(mapper.view().data());

        // ── Step 1: find "Rich" marker (plain text, not XOR'd) ─────────────
        constexpr uint32_t RICH = 0x68636952u; // "Rich"
        constexpr uint32_t DANS = 0x536E6144u; // "DanS"

        uint32_t rich_dword_idx = 0;
        for (uint32_t i = pe_offset / 4; i-- > 0x10 / 4;) {
            if (base[i] == RICH) { rich_dword_idx = i; break; }
        }
        if (rich_dword_idx == 0) return std::nullopt;

        uint32_t key = base[rich_dword_idx + 1];   // XOR key follows "Rich"

        // ── Step 2: find "DanS" by scanning backwards (decoded) ──────────
        uint32_t dans_dword_idx = 0;
        for (uint32_t i = rich_dword_idx; i-- > 0x10 / 4;) {
            if ((base[i] ^ key) == DANS) { dans_dword_idx = i; break; }
        }
        if (dans_dword_idx == 0) return std::nullopt;

        // ── Step 3: decode records between DanS+4 padding and Rich ────────
        // Skip "DanS" + 3 padding DWORDs = 4 DWORDs total
        uint32_t record_start = dans_dword_idx + 4;
        uint32_t record_end   = rich_dword_idx;

        if (record_start >= record_end ||
            (record_end - record_start) % 2 != 0)
            return std::nullopt;

        RichHeader rh;
        rh.xor_key = key;
        rh.records.reserve((record_end - record_start) / 2);

        for (uint32_t i = record_start; i + 1 < record_end; i += 2) {
            uint32_t compid     = base[i]     ^ key;
            uint32_t use_count  = base[i + 1] ^ key;

            RichRecord rec;
            rec.product_id   = static_cast<uint16_t>(compid >> 16);
            rec.build_number = static_cast<uint16_t>(compid & 0xFFFF);
            rec.use_count    = use_count;
            rh.records.push_back(rec);
        }

        if (rh.records.empty()) return std::nullopt;

        // ── Step 4: verify checksum ───────────────────────────────────────
        rh.checksum_valid = (compute_checksum(mapper, pe_offset, rh) == key);

        return rh;
    }

    // ── Toolchain inference ───────────────────────────────────────────────────

    // Human-readable name for a product ID.
    [[nodiscard]] static std::string_view product_name(uint16_t id) noexcept {
        // Representative subset; full lists at github.com/RichHeaderResearch
        switch (id) {
            case 0x0001: return "Linker/Import";
            case 0x0004: return "MASM";
            case 0x0006: return "MSVC 6.0 Linker";
            case 0x0007: return "MSVC 6.0 C";
            case 0x0008: return "MSVC 6.0 C++";
            case 0x000A: return "MSVC 7.0 C/C++";
            case 0x000C: return "MSVC 7.0 Linker";
            case 0x000E: return "MSVC 7.1 C/C++";
            case 0x000F: return "MSVC 7.1 Linker";
            case 0x0015: return "MSVC 8.0 C/C++ (VS2005)";
            case 0x0016: return "MSVC 8.0 Linker (VS2005)";
            case 0x001C: return "MSVC 9.0 C/C++ (VS2008)";
            case 0x001D: return "MSVC 9.0 Linker (VS2008)";
            case 0x0083: return "MSVC 10.0 C/C++ (VS2010)";
            case 0x0084: return "MSVC 10.0 Linker (VS2010)";
            case 0x00FF: return "MSVC 11.0 C/C++ (VS2012)";
            case 0x0100: return "MSVC 11.0 Linker (VS2012)";
            case 0x010F: return "MSVC 12.0 C/C++ (VS2013)";
            case 0x0110: return "MSVC 12.0 Linker (VS2013)";
            case 0x0167: return "MSVC 14.0 C/C++ (VS2015)";
            case 0x0168: return "MSVC 14.0 Linker (VS2015)";
            case 0x00FE: return "MSVC 11.0 Resource";
            case 0x0169: return "MSVC 14.1x Linker (VS2017)";
            case 0x016A: return "MSVC 14.2x Linker (VS2019)";
            case 0x016B: return "MSVC 14.3x Linker (VS2022)";
            case 0x0091: return "MSVC 10.0 Resource";
            case 0x009A: return "MSVC 10.0 MASM";
            default:     return "Unknown";
        }
    }

    // Summarise the dominant compiler from the records.
    [[nodiscard]] static std::string infer_compiler(const RichHeader& rh) {
        if (rh.records.empty()) return "Unknown";

        // Collect VS version hints from product IDs
        for (const auto& r : rh.records) {
            switch (r.product_id) {
                case 0x016B: return "Visual Studio 2022 (MSVC 14.3x)";
                case 0x016A: return "Visual Studio 2019 (MSVC 14.2x)";
                case 0x0169: return "Visual Studio 2017 (MSVC 14.1x)";
                case 0x0167: case 0x0168: return "Visual Studio 2015 (MSVC 14.0)";
                case 0x010F: case 0x0110: return "Visual Studio 2013 (MSVC 12.0)";
                case 0x00FF: case 0x0100: return "Visual Studio 2012 (MSVC 11.0)";
                case 0x0083: case 0x0084: return "Visual Studio 2010 (MSVC 10.0)";
                case 0x001C: case 0x001D: return "Visual Studio 2008 (MSVC 9.0)";
                case 0x0015: case 0x0016: return "Visual Studio 2005 (MSVC 8.0)";
                case 0x000E: case 0x000F: return "Visual Studio 2003 (MSVC 7.1)";
                case 0x000A: case 0x000C: return "Visual Studio 2002 (MSVC 7.0)";
                case 0x0007: case 0x0008:
                case 0x0006:              return "Visual C++ 6.0";
                default: break;
            }
        }
        return "MSVC (version unrecognised)";
    }

private:
    static uint32_t rotl32(uint32_t v, uint32_t n) noexcept {
        n &= 31;
        return (v << n) | (v >> (32 - n));
    }

    // Reproduce the MSVC checksum algorithm:
    //   sum = e_lfanew
    //   for each byte b at position i in [0, pe_offset):
    //       skip i in [0x3C, 0x40)  (the e_lfanew field itself)
    //       sum += rotl32(b, i)
    //   for each decoded (compid, count) pair:
    //       sum += rotl32(compid, count & 0x1F)
    static uint32_t compute_checksum(const FileMapper& mapper,
                                     uint32_t pe_offset,
                                     const RichHeader& rh) {
        const auto* bytes = mapper.view().data();
        uint32_t sum = pe_offset;

        for (uint32_t i = 0; i < pe_offset; ++i) {
            if (i >= 0x3C && i < 0x40) continue;
            sum += rotl32(static_cast<uint8_t>(bytes[i]), i);
        }

        for (const auto& r : rh.records) {
            uint32_t compid = (static_cast<uint32_t>(r.product_id) << 16) | r.build_number;
            sum += rotl32(compid, r.use_count & 0x1F);
        }

        return sum;
    }
};

} // namespace binview
