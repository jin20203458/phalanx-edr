#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include "SafetyWatchdog.h"

namespace Phalanx::Actuator {

struct ActuatorResult {
    bool success{false};
    uint32_t pid{0};
    std::string message;
    uint32_t threads_affected{0};
};

/**
 * @brief High-speed Win32 Process Interruption & Termination Actuator.
 *
 * Implements Early Execution Interruption via thread freezing and hard termination.
 */
class ProcessActuator {
public:
    explicit ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog = nullptr);
    ~ProcessActuator() = default;

    /**
     * @brief Freezes all execution threads of a target process within ~20ms.
     */
    ActuatorResult SuspendProcess(uint32_t pid);

    /**
     * @brief Resumes frozen threads of a target process.
     */
    ActuatorResult ResumeProcess(uint32_t pid);

    /**
     * @brief Immediately terminates a malicious process using Win32 TerminateProcess.
     */
    ActuatorResult TerminateTargetProcess(uint32_t pid, uint32_t exit_code = 1, std::string_view reason = "");

    /**
     * @brief Enumerate thread IDs for a given PID using Toolhelp32 snapshot.
     */
    static std::vector<DWORD> EnumerateProcessThreads(uint32_t pid);

    [[nodiscard]] std::shared_ptr<SafetyWatchdog> Watchdog() const noexcept {
        return watchdog_;
    }

private:
    void HandleAutoResume(uint32_t pid, const std::vector<DWORD>& thread_ids);

    std::shared_ptr<SafetyWatchdog> watchdog_;
};

} // namespace Phalanx::Actuator
