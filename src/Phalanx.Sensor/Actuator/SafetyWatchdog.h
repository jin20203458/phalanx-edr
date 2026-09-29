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

using AutoResumeCallback = std::function<void(uint32_t pid, const std::vector<DWORD>& thread_ids)>;

/**
 * @brief Safety Watchdog for SuspendThread operations.
 *
 * Prevents system deadlocks on OS loader locks (LdrpLoaderLock) by auto-resuming
 * processes if no instruction (Kill/Resume) is received from C# Core within the timeout window.
 */
class SafetyWatchdog {
public:
    explicit SafetyWatchdog(std::chrono::milliseconds default_timeout = std::chrono::milliseconds(10000));
    ~SafetyWatchdog();

    SafetyWatchdog(const SafetyWatchdog&) = delete;
    SafetyWatchdog& operator=(const SafetyWatchdog&) = delete;

    void SetAutoResumeCallback(AutoResumeCallback callback);

    /**
     * @brief Registers a suspended process and its frozen threads with the watchdog.
     */
    void RegisterSuspended(uint32_t pid, std::vector<DWORD> thread_ids, std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /**
     * @brief Refreshes keep-alive deadline during prolonged AI investigations.
     */
    bool RefreshKeepAlive(uint32_t pid, std::chrono::milliseconds extend_by = std::chrono::milliseconds(10000));

    /**
     * @brief Deregisters a suspended process when explicitly resolved (Kill or manual Resume).
     */
    bool Deregister(uint32_t pid, std::vector<DWORD>& out_threads);

    [[nodiscard]] size_t TrackedCount() const;

private:
    struct TrackedEntry {
        uint32_t pid{0};
        std::vector<DWORD> thread_ids;
        std::chrono::steady_clock::time_point deadline;
    };

    void WatchdogLoop();

    std::chrono::milliseconds default_timeout_;
    AutoResumeCallback auto_resume_callback_;

    mutable std::mutex entries_lock_;
    std::unordered_map<uint32_t, TrackedEntry> entries_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;
};

} // namespace Phalanx::Actuator
