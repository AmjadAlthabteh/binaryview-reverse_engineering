#include <catch2/catch_test_macros.hpp>

#include "core/pe_types.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <cstring>
#include <vector>

using namespace binview;

// ── PEInfo helpers ────────────────────────────────────────────────────────────

TEST_CASE("section_for_rva returns null for empty section list", "[pe_info]") {
    PEInfo info;
    REQUIRE(info.section_for_rva(0x1000) == nullptr);
}

TEST_CASE("section_for_rva finds the correct section", "[pe_info]") {
    PEInfo info;

    SectionInfo text;
    text.name            = ".text";
    text.virtual_address = 0x1000;
    text.virtual_size    = 0x5000;
    info.sections.push_back(text);

    SectionInfo data;
    data.name            = ".data";
    data.virtual_address = 0x6000;
    data.virtual_size    = 0x1000;
    info.sections.push_back(data);

    // Inside .text
    REQUIRE(info.section_for_rva(0x1000) != nullptr);
    REQUIRE(info.section_for_rva(0x1000)->name == ".text");
    REQUIRE(info.section_for_rva(0x5FFF) != nullptr);
    REQUIRE(info.section_for_rva(0x5FFF)->name == ".text");

    // Inside .data
    REQUIRE(info.section_for_rva(0x6000) != nullptr);
    REQUIRE(info.section_for_rva(0x6000)->name == ".data");

    // Gap between sections
    REQUIRE(info.section_for_rva(0x0FFF) == nullptr);

    // Beyond .data
    REQUIRE(info.section_for_rva(0x7000) == nullptr);
}

TEST_CASE("rva_to_offset computes correct file offset", "[pe_info]") {
    PEInfo info;

    SectionInfo sec;
    sec.virtual_address = 0x1000;
    sec.virtual_size    = 0x2000;
    sec.raw_offset      = 0x0200;
    sec.raw_size        = 0x2000;
    info.sections.push_back(sec);

    REQUIRE(info.rva_to_offset(0x1000).has_value());
    REQUIRE(*info.rva_to_offset(0x1000) == 0x0200);

    REQUIRE(info.rva_to_offset(0x1100).has_value());
    REQUIRE(*info.rva_to_offset(0x1100) == 0x0300);

    REQUIRE(!info.rva_to_offset(0x0FFF).has_value());
    REQUIRE(!info.rva_to_offset(0x3001).has_value());
}

// ── SectionInfo helpers ───────────────────────────────────────────────────────

TEST_CASE("SectionInfo permission string", "[section_info]") {
    SectionInfo s;
    s.characteristics = 0;
    REQUIRE(s.permissions() == "---");

    s.characteristics = IMAGE_SCN_MEM_READ;
    REQUIRE(s.permissions() == "R--");

    s.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    REQUIRE(s.permissions() == "RW-");

    s.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    REQUIRE(s.permissions() == "R-X");

    s.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    REQUIRE(s.permissions() == "RWX");
}

TEST_CASE("SectionInfo contains_rva boundary conditions", "[section_info]") {
    SectionInfo s;
    s.virtual_address = 0x1000;
    s.virtual_size    = 0x1000;  // [0x1000, 0x2000)

    REQUIRE( s.contains_rva(0x1000));
    REQUIRE( s.contains_rva(0x1FFF));
    REQUIRE(!s.contains_rva(0x0FFF));
    REQUIRE(!s.contains_rva(0x2000));
}

TEST_CASE("SectionInfo effective_size prefers virtual_size", "[section_info]") {
    SectionInfo s;
    s.virtual_size = 0x4000;
    s.raw_size     = 0x3000;
    REQUIRE(s.effective_size() == 0x4000);

    s.virtual_size = 0;
    REQUIRE(s.effective_size() == 0x3000);
}

// ── PEInfo machine / subsystem name ──────────────────────────────────────────

TEST_CASE("PEInfo machine_name returns correct strings", "[pe_info]") {
    PEInfo info;

    info.machine = MachineType::x64;
    REQUIRE(info.machine_name() == "AMD64 (x64)");

    info.machine = MachineType::x86;
    REQUIRE(info.machine_name() == "x86 (i386)");

    info.machine = MachineType::Unknown;
    REQUIRE(info.machine_name() == "Unknown");
}

TEST_CASE("PEInfo total_imported_functions sums correctly", "[pe_info]") {
    PEInfo info;

    ImportedDLL dll1;
    dll1.functions.resize(10);
    info.imports.push_back(dll1);

    ImportedDLL dll2;
    dll2.functions.resize(5);
    info.imports.push_back(dll2);

    REQUIRE(info.total_imported_functions() == 15);
}

// ── RelocationEntry ───────────────────────────────────────────────────────────

TEST_CASE("RelocationEntry target_rva computation", "[reloc]") {
    RelocationEntry r;
    r.page_rva = 0x10000;
    r.offset   = 0x0A8;
    REQUIRE(r.target_rva() == 0x100A8);
}

TEST_CASE("RelocationEntry type names", "[reloc]") {
    RelocationEntry r;
    r.type = IMAGE_REL_BASED_HIGHLOW;
    REQUIRE(r.type_name() == "HIGHLOW");

    r.type = IMAGE_REL_BASED_DIR64;
    REQUIRE(r.type_name() == "DIR64");

    r.type = IMAGE_REL_BASED_ABSOLUTE;
    REQUIRE(r.type_name() == "ABSOLUTE");
}
