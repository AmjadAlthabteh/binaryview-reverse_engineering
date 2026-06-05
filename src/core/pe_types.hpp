#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace binview {

// ── Strong typedef aliases ────────────────────────────────────────────────────

using RVA        = uint32_t;   // Relative Virtual Address
using FileOffset = uint32_t;   // Offset within the file on disk

template<typename T>
using Result = std::expected<T, std::string>;

// ── Enumerations ──────────────────────────────────────────────────────────────

enum class MachineType : uint16_t {
    Unknown = IMAGE_FILE_MACHINE_UNKNOWN,
    x86     = IMAGE_FILE_MACHINE_I386,
    ARM     = IMAGE_FILE_MACHINE_ARM,
    ARM64   = IMAGE_FILE_MACHINE_ARM64,
    x64     = IMAGE_FILE_MACHINE_AMD64,
};

enum class SubsystemType : uint16_t {
    Unknown        = IMAGE_SUBSYSTEM_UNKNOWN,
    Native         = IMAGE_SUBSYSTEM_NATIVE,
    WindowsGUI     = IMAGE_SUBSYSTEM_WINDOWS_GUI,
    WindowsCUI     = IMAGE_SUBSYSTEM_WINDOWS_CUI,
    PosixCUI       = IMAGE_SUBSYSTEM_POSIX_CUI,
    EFIApplication = IMAGE_SUBSYSTEM_EFI_APPLICATION,
    EFIBootDriver  = IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    Xbox           = IMAGE_SUBSYSTEM_XBOX,
};

// ── Section ───────────────────────────────────────────────────────────────────

struct SectionInfo {
    std::string name;
    RVA         virtual_address{};
    uint32_t    virtual_size{};
    FileOffset  raw_offset{};
    uint32_t    raw_size{};
    uint32_t    characteristics{};
    double      entropy{};

    [[nodiscard]] bool is_executable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    [[nodiscard]] bool is_readable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_READ) != 0;
    }
    [[nodiscard]] bool is_writable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }
    [[nodiscard]] bool contains_rva(RVA rva) const noexcept {
        return rva >= virtual_address && rva < virtual_address + virtual_size;
    }
    [[nodiscard]] std::string permissions() const {
        std::string p = "---";
        if (is_readable())   p[0] = 'R';
        if (is_writable())   p[1] = 'W';
        if (is_executable()) p[2] = 'X';
        return p;
    }
    [[nodiscard]] uint32_t effective_size() const noexcept {
        return virtual_size ? virtual_size : raw_size;
    }
};

// ── Imports ───────────────────────────────────────────────────────────────────

struct ImportedFunction {
    std::string name;
    uint16_t    hint{};
    bool        by_ordinal{};
    uint16_t    ordinal{};
    uint64_t    iat_va{};   // VA of the IAT slot in loaded image
};

struct ImportedDLL {
    std::string                   name;
    RVA                           descriptor_rva{};
    RVA                           iat_rva{};
    RVA                           int_rva{};
    uint32_t                      timestamp{};
    std::vector<ImportedFunction> functions;

    [[nodiscard]] bool is_bound() const noexcept {
        return timestamp == 0xFFFFFFFF;
    }
};

// ── Exports ───────────────────────────────────────────────────────────────────

struct ExportedFunction {
    std::string name;
    uint16_t    ordinal{};
    RVA         function_rva{};
    bool        forwarded{};
    std::string forwarder_string;
};

struct ExportDirectory {
    std::string                    dll_name;
    uint32_t                       ordinal_base{};
    std::vector<ExportedFunction>  functions;
};

// ── Relocations ───────────────────────────────────────────────────────────────

struct RelocationEntry {
    RVA      page_rva{};
    uint16_t type{};
    uint16_t offset{};

    [[nodiscard]] RVA target_rva() const noexcept { return page_rva + offset; }

    [[nodiscard]] std::string_view type_name() const noexcept {
        switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE: return "ABSOLUTE";
            case IMAGE_REL_BASED_HIGH:     return "HIGH";
            case IMAGE_REL_BASED_LOW:      return "LOW";
            case IMAGE_REL_BASED_HIGHLOW:  return "HIGHLOW";
            case IMAGE_REL_BASED_HIGHADJ:  return "HIGHADJ";
            case IMAGE_REL_BASED_DIR64:    return "DIR64";
            default:                       return "UNKNOWN";
        }
    }
};

// ── Analysis ──────────────────────────────────────────────────────────────────

struct AnalysisResult {
    double                   overall_entropy{};
    bool                     possibly_packed{};
    std::vector<std::string> indicators;
};

// ── Disassembled instruction ──────────────────────────────────────────────────

struct Instruction {
    uint64_t             address{};
    std::string          mnemonic;
    std::string          op_str;
    std::vector<uint8_t> bytes;
};

// ── Root PE info structure ────────────────────────────────────────────────────

struct PEInfo {
    // File metadata
    std::string file_path;
    uint64_t    file_size{};
    std::string md5;

    // PE/COFF headers
    MachineType   machine{};
    SubsystemType subsystem{};
    uint16_t      num_sections{};
    uint32_t      timestamp{};
    uint16_t      characteristics{};
    bool          is_64bit{};
    bool          is_dll{};

    // Optional header fields
    uint64_t image_base{};
    uint32_t section_alignment{};
    uint32_t file_alignment{};
    RVA      entry_point{};
    uint32_t image_size{};
    uint16_t major_linker_version{};
    uint16_t minor_linker_version{};

    std::string entry_section;  // name of section containing EP

    // Parsed components
    std::vector<SectionInfo>        sections;
    std::vector<ImportedDLL>        imports;
    std::optional<ExportDirectory>  exports;
    std::vector<RelocationEntry>    relocations;

    // Analysis results (filled by analyzers)
    AnalysisResult analysis;

    // ── Helpers ───────────────────────────────────────────────────────────────

    [[nodiscard]] const SectionInfo* section_for_rva(RVA rva) const noexcept {
        for (const auto& s : sections)
            if (s.contains_rva(rva)) return &s;
        return nullptr;
    }

    [[nodiscard]] std::optional<FileOffset> rva_to_offset(RVA rva) const noexcept {
        if (const auto* s = section_for_rva(rva))
            return s->raw_offset + (rva - s->virtual_address);
        return std::nullopt;
    }

    [[nodiscard]] std::string machine_name() const noexcept {
        switch (machine) {
            case MachineType::x86:   return "x86 (i386)";
            case MachineType::x64:   return "AMD64 (x64)";
            case MachineType::ARM:   return "ARM";
            case MachineType::ARM64: return "ARM64";
            default:                 return "Unknown";
        }
    }

    [[nodiscard]] std::string subsystem_name() const noexcept {
        switch (subsystem) {
            case SubsystemType::WindowsGUI:     return "Windows GUI";
            case SubsystemType::WindowsCUI:     return "Windows Console";
            case SubsystemType::Native:         return "Native";
            case SubsystemType::EFIApplication: return "EFI Application";
            case SubsystemType::EFIBootDriver:  return "EFI Boot Driver";
            case SubsystemType::Xbox:           return "Xbox";
            default:                            return "Unknown";
        }
    }

    [[nodiscard]] int total_imported_functions() const noexcept {
        int n = 0;
        for (const auto& dll : imports) n += static_cast<int>(dll.functions.size());
        return n;
    }
};

} // namespace binview
