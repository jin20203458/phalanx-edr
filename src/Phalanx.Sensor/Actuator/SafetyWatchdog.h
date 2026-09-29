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

#include <cstdint>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

namespace Phalanx::Actuator {

// 타임아웃 발생 시 호출될 자동 동결 해제(Auto-Resume) 콜백 시그니처
using AutoResumeCallback = std::function<void(uint32_t pid, const std::vector<DWORD>& thread_ids)>;

/**
 * @brief SuspendThread(스레드 동결) 안전 감시를 위한 비동기 세이프티 워치독.
 *
 * 타깃 프로세스가 OS 로더 락(LdrpLoaderLock)이나 크리티컬 섹션을 쥔 상태에서 비동기 동결될 경우
 * 발생할 수 있는 시스템 데드락을 방지합니다. 제한 시간(기본 10초) 내에 C# 코어로부터
 * 추가 명령(Kill/Resume)이 도착하지 않으면 자동으로 ResumeThread를 수행합니다.
 */
class SafetyWatchdog {
public:
    explicit SafetyWatchdog(std::chrono::milliseconds default_timeout = std::chrono::milliseconds(10000));
    ~SafetyWatchdog();

    SafetyWatchdog(const SafetyWatchdog&) = delete;
    SafetyWatchdog& operator=(const SafetyWatchdog&) = delete;

    // 타임아웃 발생 시 실행할 자동 복구 콜백 등록
    void SetAutoResumeCallback(AutoResumeCallback callback);

    /**
     * @brief 동결된 타깃 프로세스와 대상 스레드 ID 목록을 워치독 감시 목록에 등록
     */
    void RegisterSuspended(uint32_t pid, std::vector<DWORD> thread_ids, std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /**
     * @brief 장시간 소요되는 AI 수사 중 조기 동결 해제를 방지하기 위해 만료 시한을 연장(Keep-Alive)
     */
    bool RefreshKeepAlive(uint32_t pid, std::chrono::milliseconds extend_by = std::chrono::milliseconds(10000));

    /**
     * @brief 프로세스 종료(Kill) 또는 명시적 동결 해제 시 감시 목록에서 등록 제거
     */
    bool Deregister(uint32_t pid, std::vector<DWORD>& out_threads);

    // 현재 워치독이 감시 중인 동결 프로세스 수 반환
    [[nodiscard]] size_t TrackedCount() const;

private:
    struct TrackedEntry {
        uint32_t pid{0};
        std::vector<DWORD> thread_ids;
        std::chrono::steady_clock::time_point deadline;
    };

    // 백그라운드에서 주기적으로 만료 시한을 검사하는 감시 루프
    void WatchdogLoop();

    std::chrono::milliseconds default_timeout_;
    AutoResumeCallback auto_resume_callback_;

    mutable std::mutex entries_lock_;
    std::unordered_map<uint32_t, TrackedEntry> entries_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
};

} // namespace Phalanx::Actuator
