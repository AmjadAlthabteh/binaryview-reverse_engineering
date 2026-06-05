#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "core/pe_parser.hpp"
#include "analysis/entropy.hpp"
#include "analysis/triage.hpp"
#include "analysis/iat_reconstructor.hpp"
#include "analysis/overlay.hpp"
#include "analysis/pattern_scanner.hpp"
#include "analysis/string_extractor.hpp"
#include "analysis/rich_header.hpp"
#include "disasm/disassembler.hpp"
#include "viz/tui.hpp"
#include "viz/memory_map.hpp"
#include "export/json_exporter.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ── CLI argument schema ───────────────────────────────────────────────────────

struct Args {
    std::filesystem::path target;

    bool show_imports  = true;
    bool show_exports  = true;
    bool show_disasm   = false;
    bool show_iat      = false;
    bool show_relocs   = false;
    bool verbose       = false;
    bool json_stdout   = false;

    std::filesystem::path json_output;  // empty = no JSON file
};

void print_usage(std::string_view argv0) {
    std::printf(
        "Usage: %.*s <PE-file> [options]\n"
        "\n"
        "Options:\n"
        "  -d, --disasm       Show entry-point disassembly (Capstone)\n"
        "  -i, --iat          Show reconstructed Import Address Table\n"
        "  -r, --relocs       Show relocation summary\n"
        "  -v, --verbose      Verbose: print all imported/exported names\n"
        "  -j, --json <file>  Write JSON report to <file>\n"
        "      --json-stdout  Print JSON to stdout\n"
        "  -h, --help         Show this help\n"
        "\n",
        static_cast<int>(argv0.size()), argv0.data());
}

std::optional<Args> parse_args(int argc, char* argv[]) {
    if (argc < 2) return std::nullopt;

    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return std::nullopt;
        } else if (arg == "-d" || arg == "--disasm") {
            a.show_disasm = true;
        } else if (arg == "-i" || arg == "--iat") {
            a.show_iat = true;
        } else if (arg == "-r" || arg == "--relocs") {
            a.show_relocs = true;
        } else if (arg == "-v" || arg == "--verbose") {
            a.verbose = true;
        } else if (arg == "--json-stdout") {
            a.json_stdout = true;
        } else if ((arg == "-j" || arg == "--json") && i + 1 < argc) {
            a.json_output = argv[++i];
        } else if (arg.starts_with('-')) {
            std::fprintf(stderr, "Unknown option: %.*s\n",
                         static_cast<int>(arg.size()), arg.data());
            return std::nullopt;
        } else {
            a.target = arg;
        }
    }

    if (a.target.empty()) {
        std::fprintf(stderr, "Error: no input file specified.\n");
        return std::nullopt;
    }
    return a;
}

// ── Formatting helpers ────────────────────────────────────────────────────────

std::string humanize_duration(std::chrono::microseconds us) {
    if (us.count() < 1000) return std::format("{} µs", us.count());
    if (us.count() < 1'000'000) return std::format("{:.1f} ms", us.count() / 1000.0);
    return std::format("{:.2f} s", us.count() / 1'000'000.0);
}

} // anonymous namespace

// ── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    binview::tui::init_console();

    auto args = parse_args(argc, argv);
    if (!args) {
        print_usage(argc > 0 ? argv[0] : "binview");
        return 1;
    }

    if (!std::filesystem::exists(args->target)) {
        std::fprintf(stderr, "Error: file not found: %s\n",
                     args->target.string().c_str());
        return 1;
    }

    binview::tui::print_banner();

    // ── Parse ─────────────────────────────────────────────────────────────────

    auto t0     = std::chrono::high_resolution_clock::now();
    auto result = binview::PEParser::parse_file(args->target);
    auto t1     = std::chrono::high_resolution_clock::now();

    if (!result) {
        std::fprintf(stderr, "\n%s[!] Parse error: %s%s\n",
                     binview::tui::col::RED.data(),
                     result.error().c_str(),
                     binview::tui::col::RESET.data());
        return 1;
    }

    auto& [info, mapper] = *result;

    // ── Enrich ────────────────────────────────────────────────────────────────

    binview::EntropyAnalyzer::annotate(info, mapper);
    binview::TriageAnalyzer::run(info);

    auto t2 = std::chrono::high_resolution_clock::now();

    auto parse_ms   = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);
    auto analyze_ms = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);

    // ── Rich header (read before main display, needs pe_offset from DOS hdr) ───

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapper.view().data());
    auto rich = binview::RichHeaderParser::parse(mapper,
                    static_cast<uint32_t>(dos->e_lfanew));

    // ── Display ───────────────────────────────────────────────────────────────

    binview::tui::print_headers(info);
    binview::tui::print_rich_header(rich);
    binview::tui::print_sections(info);
    binview::tui::print_memory_map(info);
    binview::tui::print_imports(info, args->verbose);
    binview::tui::print_exports(info, args->verbose);
    binview::tui::print_triage(info);

    // ── Overlay detection (always shown) ──────────────────────────────────────

    auto overlay = binview::OverlayDetector::detect(info, mapper);
    binview::tui::print_overlay(overlay);

    // ── Pattern scan (common signatures, always shown) ────────────────────────

    auto sig_patterns    = binview::PatternScanner::common_signatures();
    auto pattern_matches = binview::PatternScanner::scan(info, mapper, sig_patterns);
    binview::tui::print_pattern_scan(pattern_matches);

    // ── String extraction (interesting strings always shown) ──────────────────

    auto strings = binview::StringExtractor::extract(info, mapper);
    binview::tui::print_strings(strings);

    if (args->show_relocs)
        binview::tui::print_relocations(info);

    // ── IAT reconstruction ────────────────────────────────────────────────────

    if (args->show_iat) {
        auto iat = binview::IATReconstructor::build(info);

        binview::tui::box_top(std::format("IMPORT ADDRESS TABLE ({} entries)", iat.size()));
        for (const auto& e : iat) {
            std::printf("%s│%s  %s\n",
                        binview::tui::col::DGRAY.data(),
                        binview::tui::col::RESET.data(),
                        binview::IATReconstructor::format_entry(e).c_str());
        }
        binview::tui::box_bottom();
        std::printf("\n");
    }

    // ── Disassembly ───────────────────────────────────────────────────────────

    if (args->show_disasm) {
        auto disasm = binview::Disassembler::disassemble_entry(info, mapper, 60);
        if (disasm) {
            binview::tui::print_disasm(*disasm, info.entry_section);
        } else {
            std::fprintf(stderr, "%s[!] Disassembly failed: %s%s\n",
                         binview::tui::col::YELLOW.data(),
                         disasm.error().c_str(),
                         binview::tui::col::RESET.data());
        }
    }

    // ── JSON export ───────────────────────────────────────────────────────────

    if (args->json_stdout || !args->json_output.empty()) {
        auto doc = binview::JsonExporter::to_json(info, overlay, pattern_matches, strings, rich);

        if (args->json_stdout)
            std::printf("%s\n", doc.dump(2).c_str());

        if (!args->json_output.empty()) {
            if (auto r = binview::JsonExporter::write_file(doc, args->json_output); !r) {
                std::fprintf(stderr, "%s[!] JSON write failed: %s%s\n",
                             binview::tui::col::RED.data(),
                             r.error().c_str(),
                             binview::tui::col::RESET.data());
            } else {
                std::printf("%s[+] JSON report saved → %s%s\n",
                            binview::tui::col::DGREEN.data(),
                            args->json_output.string().c_str(),
                            binview::tui::col::RESET.data());
            }
        }
    }

    // ── Footer ────────────────────────────────────────────────────────────────

    std::printf("%s── Timings  parse: %s  │  analyze: %s%s\n\n",
                binview::tui::col::DGRAY.data(),
                humanize_duration(parse_ms).c_str(),
                humanize_duration(analyze_ms).c_str(),
                binview::tui::col::RESET.data());

    return 0;
}
