#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <expected>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace binview {

// ── RAII wrapper for Win32 HANDLE ─────────────────────────────────────────────

struct HandleDeleter {
    // Tells unique_ptr to store a HANDLE value directly, not a HANDLE* pointer.
    using pointer = HANDLE;
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<HANDLE, HandleDeleter>;

// ── RAII wrapper for MapViewOfFile ────────────────────────────────────────────

struct MappedViewDeleter {
    void operator()(const void* p) const noexcept {
        if (p) UnmapViewOfFile(p);
    }
};
using UniqueMappedView = std::unique_ptr<const void, MappedViewDeleter>;

// ── Memory-mapped read-only file view ─────────────────────────────────────────

class FileMapper {
public:
    FileMapper() = default;
    FileMapper(const FileMapper&) = delete;
    FileMapper& operator=(const FileMapper&) = delete;
    FileMapper(FileMapper&&) noexcept = default;
    FileMapper& operator=(FileMapper&&) noexcept = default;

    [[nodiscard]] static std::expected<FileMapper, std::string>
    open(const std::filesystem::path& path) {
        FileMapper m;

        HANDLE fh = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
        if (fh == INVALID_HANDLE_VALUE)
            return std::unexpected{
                std::format("Cannot open '{}': Win32 error {}", path.string(),
                            GetLastError())};

        m.file_.reset(fh);

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(m.file_.get(), &sz))
            return std::unexpected{"GetFileSizeEx failed"};

        m.size_ = static_cast<uint64_t>(sz.QuadPart);
        if (m.size_ == 0)
            return std::unexpected{"File is empty"};
        if (m.size_ > 1ULL << 31)
            return std::unexpected{"File exceeds 2 GiB — unsupported"};

        HANDLE mh = CreateFileMappingW(m.file_.get(), nullptr, PAGE_READONLY,
                                       0, 0, nullptr);
        if (!mh)
            return std::unexpected{
                std::format("CreateFileMapping failed: {}", GetLastError())};

        m.mapping_.reset(mh);

        const void* view = MapViewOfFile(m.mapping_.get(), FILE_MAP_READ, 0, 0, 0);
        if (!view)
            return std::unexpected{
                std::format("MapViewOfFile failed: {}", GetLastError())};

        m.view_.reset(view);
        return m;
    }

    // Full file as a byte span
    [[nodiscard]] std::span<const std::byte> view() const noexcept {
        return {static_cast<const std::byte*>(view_.get()), size_};
    }

    [[nodiscard]] uint64_t size() const noexcept { return size_; }

    // Read a typed value at a given file offset; nullptr if out of range.
    template<typename T>
    [[nodiscard]] const T* read_at(size_t offset) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        if (offset + sizeof(T) > size_) return nullptr;
        return reinterpret_cast<const T*>(
            static_cast<const std::byte*>(view_.get()) + offset);
    }

    // Read a null-terminated ASCII string at a given file offset.
    [[nodiscard]] std::optional<std::string> read_cstring(size_t offset,
                                                           size_t max_len = 512) const {
        if (offset >= size_) return std::nullopt;
        const char* base  = static_cast<const char*>(view_.get());
        const char* ptr   = base + offset;
        size_t      avail = std::min<size_t>(size_ - offset, max_len);
        size_t      len   = strnlen(ptr, avail);
        if (len == avail && ptr[len] != '\0') return std::nullopt; // unterminated
        return std::string{ptr, len};
    }

private:
    UniqueHandle    file_;
    UniqueHandle    mapping_;
    UniqueMappedView view_;
    uint64_t         size_{};
};

} // namespace binview
