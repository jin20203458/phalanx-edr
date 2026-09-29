#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>

#include <string>
#include <string_view>
#include <memory>
#include <iostream>

namespace Phalanx::Common {

// ----------------------------------------------------------------------------
// RAII Wrapper for Win32 HANDLE
// ----------------------------------------------------------------------------
struct HandleDeleter {
    void operator()(HANDLE handle) const noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle);
        }
    }
};

using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

inline UniqueHandle MakeUniqueHandle(HANDLE h) noexcept {
    return UniqueHandle(h);
}

// ----------------------------------------------------------------------------
// RAII Wrapper for HMODULE
// ----------------------------------------------------------------------------
struct ModuleDeleter {
    void operator()(HMODULE hModule) const noexcept {
        if (hModule != nullptr) {
            ::FreeLibrary(hModule);
        }
    }
};

using UniqueHModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleDeleter>;

// ----------------------------------------------------------------------------
// RAII Wrapper for SC_HANDLE
// ----------------------------------------------------------------------------
struct ServiceHandleDeleter {
    void operator()(SC_HANDLE hSc) const noexcept {
        if (hSc != nullptr) {
            ::CloseServiceHandle(hSc);
        }
    }
};

using UniqueScHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceHandleDeleter>;

// ----------------------------------------------------------------------------
// Windows Privilege & Elevation Utilities
// ----------------------------------------------------------------------------
class PrivilegeHelper {
public:
    static bool IsElevated() noexcept {
        HANDLE hToken = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }
        UniqueHandle tokenGuard(hToken);

        TOKEN_ELEVATION elevation{};
        DWORD dwSize = 0;
        if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            return elevation.TokenIsElevated != 0;
        }
        return false;
    }

    static bool EnableDebugPrivilege() noexcept {
        HANDLE hToken = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }
        UniqueHandle tokenGuard(hToken);

        LUID luid{};
        if (!::LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
            return false;
        }

        return ::GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
};

// ----------------------------------------------------------------------------
// UTF-8 <-> UTF-16 Conversion Utilities
// ----------------------------------------------------------------------------
inline std::string Utf16ToUtf8(std::wstring_view wstr) {
    if (wstr.empty()) return {};
    int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};

    std::string str(sizeNeeded, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), str.data(), sizeNeeded, nullptr, nullptr);
    return str;
}

inline std::wstring Utf8ToUtf16(std::string_view str) {
    if (str.empty()) return {};
    int sizeNeeded = ::MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (sizeNeeded <= 0) return {};

    std::wstring wstr(sizeNeeded, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), wstr.data(), sizeNeeded);
    return wstr;
}

} // namespace Phalanx::Common
