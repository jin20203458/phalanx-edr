#include "SafetyWatchdog.h"
#include <iostream>

namespace Phalanx::Actuator {

SafetyWatchdog::SafetyWatchdog(std::chrono::milliseconds default_timeout)
    : default_timeout_(default_timeout),
      running_(true),
      worker_thread_(&SafetyWatchdog::WatchdogLoop, this) {
}

SafetyWatchdog::~SafetyWatchdog() {
    running_.store(false, std::memory_order_release);
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void SafetyWatchdog::SetAutoResumeCallback(AutoResumeCallback callback) {
    std::lock_guard<std::mutex> lock(entries_lock_);
    auto_resume_callback_ = std::move(callback);
}

void SafetyWatchdog::RegisterSuspended(uint32_t pid, std::vector<DWORD> thread_ids, std::chrono::milliseconds timeout) {
    if (timeout.count() <= 0) {
        timeout = default_timeout_;
    }

    std::lock_guard<std::mutex> lock(entries_lock_);
    TrackedEntry entry;
    entry.pid = pid;
    entry.thread_ids = std::move(thread_ids);
    entry.deadline = std::chrono::steady_clock::now() + timeout;

    entries_[pid] = std::move(entry);
    std::cout << "[Watchdog] PID " << pid << " registered with " << timeout.count() << "ms timeout watchdog." << std::endl;
}

bool SafetyWatchdog::RefreshKeepAlive(uint32_t pid, std::chrono::milliseconds extend_by) {
    std::lock_guard<std::mutex> lock(entries_lock_);
    auto it = entries_.find(pid);
    if (it != entries_.end()) {
        it->second.deadline = std::chrono::steady_clock::now() + extend_by;
        std::cout << "[Watchdog] PID " << pid << " keep-alive refreshed by " << extend_by.count() << "ms." << std::endl;
        return true;
    }
    return false;
}

bool SafetyWatchdog::Deregister(uint32_t pid, std::vector<DWORD>& out_threads) {
    std::lock_guard<std::mutex> lock(entries_lock_);
    auto it = entries_.find(pid);
    if (it != entries_.end()) {
        out_threads = std::move(it->second.thread_ids);
        entries_.erase(it);
        return true;
    }
    return false;
}

size_t SafetyWatchdog::TrackedCount() const {
    std::lock_guard<std::mutex> lock(entries_lock_);
    return entries_.size();
}

void SafetyWatchdog::WatchdogLoop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!running_.load(std::memory_order_relaxed)) {
            break;
        }

        std::vector<TrackedEntry> expired_entries;
        {
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(entries_lock_);
            for (auto it = entries_.begin(); it != entries_.end(); ) {
                if (now >= it->second.deadline) {
                    expired_entries.push_back(std::move(it->second));
                    it = entries_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Trigger auto-resume for expired entries
        for (const auto& expired : expired_entries) {
            std::cerr << "⚠️ [Watchdog] Orphan freeze timeout reached for PID " << expired.pid
                      << "! Triggering automatic resume to avoid loader lock deadlocks." << std::endl;
            if (auto_resume_callback_) {
                auto_resume_callback_(expired.pid, expired.thread_ids);
            }
        }
    }
}

} // namespace Phalanx::Actuator
