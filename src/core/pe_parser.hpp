#pragma once

#include "core/pe_types.hpp"
#include "core/file_mapper.hpp"

#include <algorithm>
#include <format>
#include <ranges>
#include <string_view>
#include <unordered_map>

namespace binview {

class PEParser {
public:
    // Factory — opens and fully parses a PE file.
    [[nodiscard]] static Result<std::pair<PEInfo, FileMapper>>
    parse_file(const std::filesystem::path& path) {
        auto mapper_result = FileMapper::open(path);
        if (!mapper_result) return std::unexpected{mapper_result.error()};

        FileMapper& mapper = *mapper_result;
        PEParser    parser{mapper};

        parser.info_.file_path = path.string();
        parser.info_.file_size = mapper.size();

        if (auto r = parser.parse_dos_header(); !r)
            return std::unexpected{r.error()};
        if (auto r = parser.parse_nt_headers(); !r)
            return std::unexpected{r.error()};
        if (auto r = parser.parse_sections(); !r)
            return std::unexpected{r.error()};

        parser.parse_imports();
        parser.parse_exports();
        parser.parse_relocations();
        parser.finalize();

        return std::pair{std::move(parser.info_), std::move(*mapper_result)};
    }

private:
    explicit PEParser(const FileMapper& m) : mapper_{m} {}

    const FileMapper& mapper_;
    PEInfo            info_;

    // Cached header pointers
    const IMAGE_NT_HEADERS32* nt32_{};
    const IMAGE_NT_HEADERS64* nt64_{};
    size_t                    pe_offset_{};

    // ── DOS Header ────────────────────────────────────────────────────────────

    Result<void> parse_dos_header() {
        const auto* dos = mapper_.read_at<IMAGE_DOS_HEADER>(0);
        if (!dos)
            return std::unexpected{"File too small for DOS header"};
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return std::unexpected{
                std::format("Invalid DOS magic: 0x{:04X} (expected 0x5A4D)",
                            dos->e_magic)};
        pe_offset_ = static_cast<size_t>(dos->e_lfanew);
        return {};
    }

    // ── NT Headers ────────────────────────────────────────────────────────────

    Result<void> parse_nt_headers() {
        const auto* sig = mapper_.read_at<uint32_t>(pe_offset_);
        if (!sig)
            return std::unexpected{"File too small for PE signature"};
        if (*sig != IMAGE_NT_SIGNATURE)
            return std::unexpected{
                std::format("Invalid PE signature: 0x{:08X}", *sig)};

        constexpr size_t fh_off = sizeof(uint32_t);
        const auto* fh = mapper_.read_at<IMAGE_FILE_HEADER>(pe_offset_ + fh_off);
        if (!fh)
            return std::unexpected{"File too small for FILE_HEADER"};

        info_.machine         = static_cast<MachineType>(fh->Machine);
        info_.num_sections    = fh->NumberOfSections;
        info_.timestamp       = fh->TimeDateStamp;
        info_.characteristics = fh->Characteristics;
        info_.is_dll          = (fh->Characteristics & IMAGE_FILE_DLL) != 0;

        constexpr size_t opt_off = fh_off + sizeof(IMAGE_FILE_HEADER);
        const auto* magic = mapper_.read_at<uint16_t>(pe_offset_ + opt_off);
        if (!magic)
            return std::unexpected{"File too small for optional header magic"};

        if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            info_.is_64bit = true;
            nt64_ = mapper_.read_at<IMAGE_NT_HEADERS64>(pe_offset_);
            if (!nt64_)
                return std::unexpected{"File too small for 64-bit NT headers"};
            apply_opt64(nt64_->OptionalHeader);

        } else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            info_.is_64bit = false;
            nt32_ = mapper_.read_at<IMAGE_NT_HEADERS32>(pe_offset_);
            if (!nt32_)
                return std::unexpected{"File too small for 32-bit NT headers"};
            apply_opt32(nt32_->OptionalHeader);

        } else {
            return std::unexpected{
                std::format("Unknown optional header magic: 0x{:04X}", *magic)};
        }
        return {};
    }

    void apply_opt64(const IMAGE_OPTIONAL_HEADER64& opt) {
        info_.image_base            = opt.ImageBase;
        info_.section_alignment     = opt.SectionAlignment;
        info_.file_alignment        = opt.FileAlignment;
        info_.entry_point           = opt.AddressOfEntryPoint;
        info_.image_size            = opt.SizeOfImage;
        info_.subsystem             = static_cast<SubsystemType>(opt.Subsystem);
        info_.major_linker_version  = opt.MajorLinkerVersion;
        info_.minor_linker_version  = opt.MinorLinkerVersion;
    }

    void apply_opt32(const IMAGE_OPTIONAL_HEADER32& opt) {
        info_.image_base            = opt.ImageBase;
        info_.section_alignment     = opt.SectionAlignment;
        info_.file_alignment        = opt.FileAlignment;
        info_.entry_point           = opt.AddressOfEntryPoint;
        info_.image_size            = opt.SizeOfImage;
        info_.subsystem             = static_cast<SubsystemType>(opt.Subsystem);
        info_.major_linker_version  = opt.MajorLinkerVersion;
        info_.minor_linker_version  = opt.MinorLinkerVersion;
    }

    // ── Sections ─────────────────────────────────────────────────────────────

    Result<void> parse_sections() {
        uint16_t opt_size = info_.is_64bit ? nt64_->FileHeader.SizeOfOptionalHeader
                                           : nt32_->FileHeader.SizeOfOptionalHeader;

        size_t tbl = pe_offset_ + sizeof(uint32_t)
                   + sizeof(IMAGE_FILE_HEADER) + opt_size;

        info_.sections.reserve(info_.num_sections);

        for (uint16_t i = 0; i < info_.num_sections; ++i) {
            const auto* h = mapper_.read_at<IMAGE_SECTION_HEADER>(
                tbl + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER));
            if (!h) break;

            SectionInfo sec;
            sec.name = std::string{
                reinterpret_cast<const char*>(h->Name),
                strnlen(reinterpret_cast<const char*>(h->Name), IMAGE_SIZEOF_SHORT_NAME)
            };
            sec.virtual_address = h->VirtualAddress;
            sec.virtual_size    = h->Misc.VirtualSize;
            sec.raw_offset      = h->PointerToRawData;
            sec.raw_size        = h->SizeOfRawData;
            sec.characteristics = h->Characteristics;

            info_.sections.push_back(std::move(sec));
        }
        return {};
    }

    // ── Data directory helper ─────────────────────────────────────────────────

    [[nodiscard]] std::optional<IMAGE_DATA_DIRECTORY>
    data_dir(uint32_t idx) const noexcept {
        const IMAGE_DATA_DIRECTORY* arr = nullptr;
        uint32_t                    cnt = 0;

        if (info_.is_64bit && nt64_) {
            arr = nt64_->OptionalHeader.DataDirectory;
            cnt = nt64_->OptionalHeader.NumberOfRvaAndSizes;
        } else if (nt32_) {
            arr = nt32_->OptionalHeader.DataDirectory;
            cnt = nt32_->OptionalHeader.NumberOfRvaAndSizes;
        }

        if (!arr || idx >= cnt) return std::nullopt;
        if (arr[idx].VirtualAddress == 0) return std::nullopt;
        return arr[idx];
    }

    [[nodiscard]] std::optional<FileOffset> rva2off(RVA rva) const noexcept {
        return info_.rva_to_offset(rva);
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    void parse_imports() {
        auto dir = data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!dir) return;

        auto base_off = rva2off(dir->VirtualAddress);
        if (!base_off) return;

        for (size_t i = 0;; ++i) {
            size_t desc_off = *base_off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            const auto* d = mapper_.read_at<IMAGE_IMPORT_DESCRIPTOR>(desc_off);
            if (!d || (d->OriginalFirstThunk == 0 && d->FirstThunk == 0)) break;

            ImportedDLL dll;
            dll.descriptor_rva = dir->VirtualAddress
                                + static_cast<RVA>(i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            dll.iat_rva        = d->FirstThunk;
            dll.int_rva        = d->OriginalFirstThunk;
            dll.timestamp      = d->TimeDateStamp;

            if (auto noff = rva2off(d->Name))
                dll.name = mapper_.read_cstring(*noff).value_or("<unknown>");

            RVA thunk_rva = d->OriginalFirstThunk ? d->OriginalFirstThunk
                                                   : d->FirstThunk;
            fill_thunks(dll, thunk_rva, d->FirstThunk);
            info_.imports.push_back(std::move(dll));
        }
    }

    void fill_thunks(ImportedDLL& dll, RVA int_rva, RVA iat_rva) {
        auto int_off = rva2off(int_rva);
        if (!int_off) return;

        const size_t entry_sz = info_.is_64bit ? sizeof(uint64_t) : sizeof(uint32_t);

        for (size_t i = 0;; ++i) {
            size_t off = *int_off + i * entry_sz;
            ImportedFunction fn;
            fn.iat_va = info_.image_base + iat_rva + i * entry_sz;

            if (info_.is_64bit) {
                const auto* thunk = mapper_.read_at<IMAGE_THUNK_DATA64>(off);
                if (!thunk || thunk->u1.AddressOfData == 0) break;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    fn.by_ordinal = true;
                    fn.ordinal    = IMAGE_ORDINAL64(thunk->u1.Ordinal);
                    fn.name       = std::format("Ordinal#{}", fn.ordinal);
                } else {
                    load_ibn(fn, static_cast<RVA>(thunk->u1.AddressOfData));
                }
            } else {
                const auto* thunk = mapper_.read_at<IMAGE_THUNK_DATA32>(off);
                if (!thunk || thunk->u1.AddressOfData == 0) break;
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    fn.by_ordinal = true;
                    fn.ordinal    = IMAGE_ORDINAL32(thunk->u1.Ordinal);
                    fn.name       = std::format("Ordinal#{}", fn.ordinal);
                } else {
                    load_ibn(fn, static_cast<RVA>(thunk->u1.AddressOfData));
                }
            }
            dll.functions.push_back(std::move(fn));
        }
    }

    void load_ibn(ImportedFunction& fn, RVA ibn_rva) {
        auto off = rva2off(ibn_rva);
        if (!off) return;
        const auto* ibn = mapper_.read_at<IMAGE_IMPORT_BY_NAME>(*off);
        if (!ibn) return;
        fn.hint = ibn->Hint;
        // Name immediately follows the Hint WORD
        fn.name = mapper_.read_cstring(*off + offsetof(IMAGE_IMPORT_BY_NAME, Name))
                          .value_or("<bad_name>");
    }

    // ── Exports ───────────────────────────────────────────────────────────────

    void parse_exports() {
        auto dir = data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (!dir) return;

        auto off = rva2off(dir->VirtualAddress);
        if (!off) return;

        const auto* exp = mapper_.read_at<IMAGE_EXPORT_DIRECTORY>(*off);
        if (!exp) return;

        ExportDirectory result;
        result.ordinal_base = exp->Base;

        if (auto noff = rva2off(exp->Name))
            result.dll_name = mapper_.read_cstring(*noff).value_or("<unknown>");

        auto fn_arr   = rva2off(exp->AddressOfFunctions);
        auto name_arr = rva2off(exp->AddressOfNames);
        auto ord_arr  = rva2off(exp->AddressOfNameOrdinals);
        if (!fn_arr) return;

        // Build ordinal-index → export name map
        std::unordered_map<uint16_t, std::string> ord2name;
        if (name_arr && ord_arr) {
            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                const auto* nrva = mapper_.read_at<uint32_t>(*name_arr + i * 4);
                const auto* idx  = mapper_.read_at<uint16_t>(*ord_arr  + i * 2);
                if (!nrva || !idx) break;
                if (auto soff = rva2off(*nrva))
                    if (auto s = mapper_.read_cstring(*soff))
                        ord2name[*idx] = std::move(*s);
            }
        }

        for (uint32_t i = 0; i < exp->NumberOfFunctions; ++i) {
            const auto* fn_rva = mapper_.read_at<uint32_t>(*fn_arr + i * 4);
            if (!fn_rva || *fn_rva == 0) continue;

            ExportedFunction fn;
            fn.ordinal      = static_cast<uint16_t>(exp->Base + i);
            fn.function_rva = *fn_rva;

            if (auto it = ord2name.find(static_cast<uint16_t>(i));
                it != ord2name.end())
                fn.name = it->second;
            else
                fn.name = std::format("Ordinal#{}", fn.ordinal);

            // Forwarder: function RVA falls inside the export directory
            if (*fn_rva >= dir->VirtualAddress &&
                *fn_rva <  dir->VirtualAddress + dir->Size) {
                fn.forwarded = true;
                if (auto foff = rva2off(*fn_rva))
                    fn.forwarder_string = mapper_.read_cstring(*foff).value_or("");
            }

            result.functions.push_back(std::move(fn));
        }

        info_.exports = std::move(result);
    }

    // ── Relocations ───────────────────────────────────────────────────────────

    void parse_relocations() {
        auto dir = data_dir(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (!dir) return;

        auto start = rva2off(dir->VirtualAddress);
        if (!start) return;

        size_t cursor = *start;
        size_t end    = *start + dir->Size;

        while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            const auto* blk = mapper_.read_at<IMAGE_BASE_RELOCATION>(cursor);
            if (!blk || blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            RVA      page_rva = blk->VirtualAddress;
            uint32_t n_entries =
                (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

            for (uint32_t i = 0; i < n_entries; ++i) {
                const auto* entry = mapper_.read_at<uint16_t>(
                    cursor + sizeof(IMAGE_BASE_RELOCATION) + i * 2);
                if (!entry) break;

                uint16_t type   = (*entry >> 12) & 0xF;
                uint16_t offset = *entry & 0x0FFF;

                if (type != IMAGE_REL_BASED_ABSOLUTE)
                    info_.relocations.push_back({page_rva, type, offset});
            }
            cursor += blk->SizeOfBlock;
        }
    }

    // ── Finalize ─────────────────────────────────────────────────────────────

    void finalize() {
        if (const auto* s = info_.section_for_rva(info_.entry_point))
            info_.entry_section = s->name;
    }
};

} // namespace binview
