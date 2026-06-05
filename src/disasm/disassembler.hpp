#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <capstone/capstone.h>
#include <format>
#include <string>
#include <vector>

namespace binview {

// ── RAII wrapper for Capstone handle ─────────────────────────────────────────

class CsHandle {
public:
    CsHandle() = default;
    ~CsHandle() { if (open_) cs_close(&h_); }

    CsHandle(const CsHandle&) = delete;
    CsHandle& operator=(const CsHandle&) = delete;
    CsHandle(CsHandle&& o) noexcept : h_{o.h_}, open_{o.open_} { o.open_ = false; }

    [[nodiscard]] Result<void> open(cs_arch arch, cs_mode mode) {
        if (cs_err err = cs_open(arch, mode, &h_); err != CS_ERR_OK)
            return std::unexpected{
                std::format("cs_open: {}", cs_strerror(err))};
        open_ = true;
        cs_option(h_, CS_OPT_SKIPDATA, CS_OPT_ON);
        return {};
    }

    [[nodiscard]] csh get() const noexcept { return h_; }

private:
    csh  h_{};
    bool open_{false};
};

// ── RAII for cs_insn* array ───────────────────────────────────────────────────

struct CsInsnBlock {
    cs_insn* ptr{};
    size_t   count{};

    CsInsnBlock() = default;
    CsInsnBlock(cs_insn* p, size_t c) : ptr{p}, count{c} {}
    ~CsInsnBlock() { if (ptr) cs_free(ptr, count); }

    CsInsnBlock(const CsInsnBlock&) = delete;
    CsInsnBlock& operator=(const CsInsnBlock&) = delete;
};

// ── Disassembler ─────────────────────────────────────────────────────────────

class Disassembler {
public:
    struct Config {
        size_t max_instructions{50};
        RVA    start_rva{0};    // 0 = section start
    };

    // Disassemble up to cfg.max_instructions starting at cfg.start_rva.
    [[nodiscard]] static Result<std::vector<Instruction>>
    disassemble(const PEInfo& info, const FileMapper& mapper,
                const SectionInfo& section, const Config& cfg = {}) {

        CsHandle cs;
        if (auto r = cs.open(CS_ARCH_X86,
                              info.is_64bit ? CS_MODE_64 : CS_MODE_32); !r)
            return std::unexpected{r.error()};

        auto file_view = mapper.view();
        if (section.raw_offset >= file_view.size())
            return std::unexpected{"Section raw data not in file"};

        size_t   avail     = file_view.size() - section.raw_offset;
        size_t   raw_limit = std::min<size_t>(section.raw_size, avail);
        uint32_t inner_off = 0;

        if (cfg.start_rva) {
            if (cfg.start_rva < section.virtual_address)
                return std::unexpected{"start_rva before section"};
            inner_off = cfg.start_rva - section.virtual_address;
            if (inner_off >= raw_limit)
                return std::unexpected{"start_rva beyond section raw data"};
        }

        const uint8_t* code = reinterpret_cast<const uint8_t*>(
            file_view.data() + section.raw_offset + inner_off);
        size_t   code_size = raw_limit - inner_off;
        uint64_t base_va   = info.image_base + section.virtual_address + inner_off;

        cs_insn* raw = nullptr;
        size_t   n   = cs_disasm(cs.get(), code, code_size, base_va,
                                 cfg.max_instructions, &raw);

        CsInsnBlock block{raw, n};  // RAII

        if (n == 0) {
            cs_err e = cs_errno(cs.get());
            if (e != CS_ERR_OK)
                return std::unexpected{std::format("cs_disasm: {}", cs_strerror(e))};
            return std::vector<Instruction>{};
        }

        std::vector<Instruction> result;
        result.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            Instruction ins;
            ins.address  = block.ptr[i].address;
            ins.mnemonic = block.ptr[i].mnemonic;
            ins.op_str   = block.ptr[i].op_str;
            ins.bytes.assign(block.ptr[i].bytes,
                             block.ptr[i].bytes + block.ptr[i].size);
            result.push_back(std::move(ins));
        }
        return result;
    }

    // Convenience: disassemble the section that contains the entry point.
    [[nodiscard]] static Result<std::vector<Instruction>>
    disassemble_entry(const PEInfo& info, const FileMapper& mapper,
                      size_t max_insns = 50) {
        const auto* sec = info.section_for_rva(info.entry_point);
        if (!sec) return std::unexpected{"Entry point not in any section"};
        Config cfg{max_insns, info.entry_point};
        return disassemble(info, mapper, *sec, cfg);
    }
};

} // namespace binview
