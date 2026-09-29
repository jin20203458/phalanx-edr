#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

int main(int argc, char* argv[]) {
    std::string canary_path;
    int delay_us = 800; // 0.8ms (0.5~1ms 네이티브 공격 윈도우 시뮬레이션)

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--canary" && i + 1 < argc) {
            canary_path = argv[++i];
        } else if (arg == "--delay-us" && i + 1 < argc) {
            delay_us = std::stoi(argv[++i]);
        }
    }

    if (canary_path.empty()) {
        std::cerr << "Usage: MockNativeRansomware.exe --canary <filepath> [--delay-us <microseconds>] [vssadmin delete shadows]" << std::endl;
        return 1;
    }

    // 0.5~1ms 공격 윈도우: PE 로더 완료 및 main() 진입 후 디스크 쓰기 직전 웜업
    if (delay_us > 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(delay_us));
    }

    // 카나리 파일 생성 및 쓰기 시도
    HANDLE hFile = ::CreateFileA(
        canary_path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char payload[] = "PWNED BY MOCK RANSOMWARE (CANARY LEAK)";
        DWORD bytesWritten = 0;
        ::WriteFile(hFile, payload, static_cast<DWORD>(sizeof(payload) - 1), &bytesWritten, nullptr);
        ::CloseHandle(hFile);
        return 0; // 카나리 파일 생성 완료 (EDR 미탐 시)
    }

    return 2;
}
