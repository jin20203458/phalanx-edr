#include "ProcessActuator.h"
#include "../Common/Win32Handles.h"
#include <tlhelp32.h>
#include <iostream>

namespace Phalanx::Actuator {

ProcessActuator::ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog)
    : watchdog_(std::move(watchdog)) {
    if (watchdog_) {
        watchdog_->SetAutoResumeCallback([this](uint32_t pid, const std::vector<DWORD>& thread_ids) {
            this->HandleAutoResume(pid, thread_ids);
        });
    }
}

std::vector<DWORD> ProcessActuator::EnumerateProcessThreads(uint32_t pid) {
    std::vector<DWORD> thread_ids;
    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return thread_ids;
    }
    Common::UniqueHandle snapGuard(hSnap);

    THREADENTRY32 te32{};
    te32.dwSize = sizeof(THREADENTRY32);

    if (::Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                thread_ids.push_back(te32.th32ThreadID);
            }
        } while (::Thread32Next(hSnap, &te32));
    }

    return thread_ids;
}

ActuatorResult ProcessActuator::SuspendProcess(uint32_t pid) {
    ActuatorResult result;
    result.pid = pid;

    std::vector<DWORD> tids = EnumerateProcessThreads(pid);
    if (tids.empty()) {
        result.success = false;
        result.message = "No threads found for target PID (process may have already exited)";
        return result;
    }

    std::vector<DWORD> suspended_tids;
    for (DWORD tid : tids) {
        HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) {
            continue;
        }
        Common::UniqueHandle threadGuard(hThread);

        DWORD prev_suspend_count = ::SuspendThread(hThread);
        if (prev_suspend_count != static_cast<DWORD>(-1)) {
            suspended_tids.push_back(tid);
        }
    }

    if (suspended_tids.empty()) {
        result.success = false;
        result.message = "Failed to suspend any threads in target process";
        return result;
    }

    result.threads_affected = static_cast<uint32_t>(suspended_tids.size());
    result.success = true;
    result.message = "Target process successfully frozen";

    if (watchdog_) {
        watchdog_->RegisterSuspended(pid, std::move(suspended_tids));
    }

    return result;
}

ActuatorResult ProcessActuator::ResumeProcess(uint32_t pid) {
    ActuatorResult result;
    result.pid = pid;

    std::vector<DWORD> tids;
    bool had_watchdog_entry = false;

    if (watchdog_) {
        had_watchdog_entry = watchdog_->Deregister(pid, tids);
    }

    // Fallback: If not in watchdog, enumerate existing threads
    if (!had_watchdog_entry || tids.empty()) {
        tids = EnumerateProcessThreads(pid);
    }

    uint32_t resumed_count = 0;
    for (DWORD tid : tids) {
        HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) {
            continue;
        }
        Common::UniqueHandle threadGuard(hThread);

        DWORD prev_count = ::ResumeThread(hThread);
        if (prev_count != static_cast<DWORD>(-1)) {
            resumed_count++;
        }
    }

    result.threads_affected = resumed_count;
    result.success = (resumed_count > 0);
    result.message = result.success ? "Target process resumed" : "Failed to resume threads";
    return result;
}

ActuatorResult ProcessActuator::TerminateTargetProcess(uint32_t pid, uint32_t exit_code, std::string_view reason) {
    ActuatorResult result;
    result.pid = pid;

    // Deregister from watchdog if frozen
    if (watchdog_) {
        std::vector<DWORD> dummy;
        watchdog_->Deregister(pid, dummy);
    }

    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        DWORD err = ::GetLastError();
        result.success = false;
        result.message = "OpenProcess failed (Error code: " + std::to_string(err) + ")";
        return result;
    }
    Common::UniqueHandle procGuard(hProcess);

    if (::TerminateProcess(hProcess, exit_code)) {
        result.success = true;
        result.message = "Process terminated successfully";
        if (!reason.empty()) {
            result.message += " (Reason: " + std::string(reason) + ")";
        }
        std::cout << "🛡️ [Actuator] Terminated malicious PID " << pid << " (" << result.message << ")" << std::endl;
    } else {
        DWORD err = ::GetLastError();
        result.success = false;
        result.message = "TerminateProcess failed (Error code: " + std::to_string(err) + ")";
    }

    return result;
}

void ProcessActuator::HandleAutoResume(uint32_t pid, const std::vector<DWORD>& thread_ids) {
    for (DWORD tid : thread_ids) {
        HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            Common::UniqueHandle guard(hThread);
            ::ResumeThread(hThread);
        }
    }
    std::cout << "[Actuator] Auto-resumed " << thread_ids.size() << " threads for orphan PID " << pid << std::endl;
}

} // namespace Phalanx::Actuator
