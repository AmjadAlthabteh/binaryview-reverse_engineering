#pragma once

#include "core/pe_types.hpp"

#include <format>
#include <string>
#include <vector>

namespace binview {

// Represents one entry in the reconstructed IAT as it would appear
// in a loaded (but not yet resolved) image.
struct IATEntry {
    uint64_t    slot_va;        // VA of this pointer slot in the loaded image
    std::string dll_name;       // Owning DLL
    std::string function_name;  // Function name or "Ordinal#N"
    bool        by_ordinal{};
    uint16_t    ordinal{};
    uint16_t    hint{};
};

// Flat, ordered view of every IAT slot across all import descriptors.
class IATReconstructor {
public:
    [[nodiscard]] static std::vector<IATEntry> build(const PEInfo& info) {
        std::vector<IATEntry> table;
        table.reserve(static_cast<size_t>(info.total_imported_functions()));

        for (const auto& dll : info.imports) {
            for (const auto& fn : dll.functions) {
                IATEntry e;
                e.slot_va       = fn.iat_va;
                e.dll_name      = dll.name;
                e.function_name = fn.name;
                e.by_ordinal    = fn.by_ordinal;
                e.ordinal       = fn.ordinal;
                e.hint          = fn.hint;
                table.push_back(std::move(e));
            }
        }

        // Sort by slot VA for linear IAT traversal order
        std::ranges::sort(table, {}, &IATEntry::slot_va);
        return table;
    }

    // Format one entry as a human-readable line
    [[nodiscard]] static std::string format_entry(const IATEntry& e) {
        if (e.by_ordinal)
            return std::format("  [{:#018x}]  {}  ->  Ordinal #{:<5}  ({})",
                               e.slot_va, e.dll_name, e.ordinal, e.dll_name);
        return std::format("  [{:#018x}]  {}  ->  {} (hint={:#x})",
                           e.slot_va, e.dll_name, e.function_name, e.hint);
    }
};

} // namespace binview
