#pragma once

#include "core/pe_types.hpp"
#include "analysis/entropy.hpp"
#include "analysis/overlay.hpp"
#include "analysis/pattern_scanner.hpp"
#include "analysis/string_extractor.hpp"
#include "analysis/rich_header.hpp"

#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>

namespace binview {

using json = nlohmann::ordered_json;

class JsonExporter {
public:
    [[nodiscard]] static json to_json(
            const PEInfo& info,
            const std::optional<OverlayInfo>&      overlay = std::nullopt,
            const std::vector<PatternMatch>&        matches = {},
            const std::vector<ExtractedString>&     strings = {},
            const std::optional<RichHeader>&        rich    = std::nullopt) {
        json root;

        root["generator"] = "BinView v1.0";
        root["generated_at"] = iso8601_now();

        // ── File ──────────────────────────────────────────────────────────────
        root["file"] = {
            {"path",     info.file_path},
            {"size",     info.file_size},
        };

        // ── Headers ───────────────────────────────────────────────────────────
        root["headers"] = {
            {"machine",            info.machine_name()},
            {"subsystem",          info.subsystem_name()},
            {"is_64bit",           info.is_64bit},
            {"is_dll",             info.is_dll},
            {"image_base",         std::format("{:#x}", info.image_base)},
            {"entry_point",        std::format("{:#x}", info.entry_point)},
            {"entry_section",      info.entry_section},
            {"image_size",         info.image_size},
            {"section_alignment",  info.section_alignment},
            {"file_alignment",     info.file_alignment},
            {"timestamp",          info.timestamp},
            {"num_sections",       info.num_sections},
            {"linker_version",     std::format("{}.{}",
                                               info.major_linker_version,
                                               info.minor_linker_version)},
        };

        // ── Sections ──────────────────────────────────────────────────────────
        auto& secs = root["sections"] = json::array();
        for (const auto& sec : info.sections) {
            secs.push_back({
                {"name",             sec.name},
                {"virtual_address",  std::format("{:#x}", sec.virtual_address)},
                {"virtual_size",     sec.virtual_size},
                {"raw_offset",       std::format("{:#x}", sec.raw_offset)},
                {"raw_size",         sec.raw_size},
                {"permissions",      sec.permissions()},
                {"entropy",          sec.entropy},
                {"entropy_level",    std::string{
                    EntropyAnalyzer::level_label(
                        EntropyAnalyzer::classify(sec.entropy))}},
                {"flags", {
                    {"readable",    sec.is_readable()},
                    {"writable",    sec.is_writable()},
                    {"executable",  sec.is_executable()},
                }},
            });
        }

        // ── Imports ───────────────────────────────────────────────────────────
        auto& imps = root["imports"] = json::array();
        for (const auto& dll : info.imports) {
            json dll_obj = {
                {"name",            dll.name},
                {"descriptor_rva",  std::format("{:#x}", dll.descriptor_rva)},
                {"iat_rva",         std::format("{:#x}", dll.iat_rva)},
                {"int_rva",         std::format("{:#x}", dll.int_rva)},
                {"bound",           dll.is_bound()},
            };
            auto& fns = dll_obj["functions"] = json::array();
            for (const auto& fn : dll.functions) {
                json fn_obj = {
                    {"name",       fn.name},
                    {"iat_va",     std::format("{:#x}", fn.iat_va)},
                    {"by_ordinal", fn.by_ordinal},
                };
                if (fn.by_ordinal)
                    fn_obj["ordinal"] = fn.ordinal;
                else
                    fn_obj["hint"] = fn.hint;
                fns.push_back(std::move(fn_obj));
            }
            imps.push_back(std::move(dll_obj));
        }

        // ── Exports ───────────────────────────────────────────────────────────
        if (info.exports) {
            const auto& exp = *info.exports;
            json exp_obj = {
                {"dll_name",     exp.dll_name},
                {"ordinal_base", exp.ordinal_base},
            };
            auto& fns = exp_obj["functions"] = json::array();
            for (const auto& fn : exp.functions) {
                json fn_obj = {
                    {"name",         fn.name},
                    {"ordinal",      fn.ordinal},
                    {"function_rva", std::format("{:#x}", fn.function_rva)},
                    {"forwarded",    fn.forwarded},
                };
                if (fn.forwarded)
                    fn_obj["forwarder"] = fn.forwarder_string;
                fns.push_back(std::move(fn_obj));
            }
            root["exports"] = std::move(exp_obj);
        } else {
            root["exports"] = nullptr;
        }

        // ── Relocations summary ───────────────────────────────────────────────
        root["relocations"] = {
            {"count", info.relocations.size()},
        };

        // ── Analysis ─────────────────────────────────────────────────────────
        root["analysis"] = {
            {"overall_entropy",  info.analysis.overall_entropy},
            {"possibly_packed",  info.analysis.possibly_packed},
            {"indicators",       info.analysis.indicators},
        };

        // ── Overlay ───────────────────────────────────────────────────────────
        if (overlay) {
            root["overlay"] = {
                {"offset",      std::format("{:#x}", overlay->offset)},
                {"size",        overlay->size},
                {"entropy",     overlay->entropy},
                {"magic",       overlay->magic_string()},
                {"fingerprint", overlay->fingerprint()},
            };
        } else {
            root["overlay"] = nullptr;
        }

        // ── Pattern matches ───────────────────────────────────────────────────
        auto& pm = root["pattern_matches"] = json::array();
        for (const auto& m : matches) {
            pm.push_back({
                {"pattern",     m.pattern_name},
                {"section",     m.section_name},
                {"va",          std::format("{:#x}", m.va)},
                {"file_offset", std::format("{:#x}", m.file_offset)},
            });
        }

        // ── Strings ───────────────────────────────────────────────────────────
        auto& ss = root["strings"] = json::array();
        for (const auto& s : strings) {
            ss.push_back({
                {"value",       s.value},
                {"kind",        std::string{s.kind_label().empty()
                                            ? "plain" : s.kind_label()}},
                {"wide",        s.wide},
                {"section",     s.section_name},
                {"va",          std::format("{:#x}", s.va)},
                {"file_offset", std::format("{:#x}", s.file_offset)},
            });
        }

        // ── Rich header ───────────────────────────────────────────────────────
        if (rich) {
            json robj = {
                {"xor_key",         std::format("{:#010x}", rich->xor_key)},
                {"checksum_valid",  rich->checksum_valid},
                {"compiler",        RichHeaderParser::infer_compiler(*rich)},
            };
            auto& recs = robj["records"] = json::array();
            for (const auto& r : rich->records) {
                recs.push_back({
                    {"product_id",   r.product_id},
                    {"build_number", r.build_number},
                    {"use_count",    r.use_count},
                    {"tool",         std::string{RichHeaderParser::product_name(r.product_id)}},
                });
            }
            root["rich_header"] = std::move(robj);
        } else {
            root["rich_header"] = nullptr;
        }

        return root;
    }

    [[nodiscard]] static Result<void>
    write_file(const json& doc, const std::filesystem::path& out) {
        std::ofstream f{out};
        if (!f.is_open())
            return std::unexpected{
                std::format("Cannot open '{}' for writing", out.string())};
        f << doc.dump(2) << '\n';
        return {};
    }

private:
    static std::string iso8601_now() {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tm_val{};
        gmtime_s(&tm_val, &time);
        char buf[32]{};
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_val);
        return buf;
    }
};

} // namespace binview
