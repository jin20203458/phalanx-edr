#include "ProcessActuator.h"
#include "../Common/Win32Handles.h"
#include <tlhelp32.h>
#include <iostream>

namespace Phalanx::Actuator {

ProcessActuator::ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog)
    : watchdog_(std::move(watchdog)) {
    if (watchdog_) {
        // 워치독 타임아웃 만료 시 호출될 자동 복구 핸들러 등록
        watchdog_->SetAutoResumeCallback([this](uint32_t pid, const std::vector<DWORD>& thread_ids) {
            this->HandleAutoResume(pid, thread_ids);
        });
    }
}

std::vector<DWORD> ProcessActuator::EnumerateProcessThreads(uint32_t pid) {
    std::vector<DWORD> thread_ids;
    // 시스템 전체 스레드 스냅샷 생성
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

    // 타깃 프로세스에 속한 모든 스레드 식별
    std::vector<DWORD> tids = EnumerateProcessThreads(pid);
    if (tids.empty()) {
        result.success = false;
        result.message = "대상 PID의 스레드를 찾을 수 없습니다 (프로세스가 이미 종료되었을 수 있음)";
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
        result.message = "타깃 프로세스의 스레드를 동결하지 못했습니다";
        return result;
    }

    result.threads_affected = static_cast<uint32_t>(suspended_tids.size());
    result.success = true;
    result.message = "타깃 프로세스가 성공적으로 동결(Freeze)되었습니다";

    // 동결 성공 시 OS 로더 락 데드락 방지를 위해 세이프티 워치독에 등록
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

    // 워치독에서 대상 프로세스를 등록 해제하며 동결된 스레드 목록 회수
    if (watchdog_) {
        had_watchdog_entry = watchdog_->Deregister(pid, tids);
    }

    // 워치독에 없는 경우 현재 존재하는 스레드를 직접 열거하여 복구
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
    result.message = result.success ? "타깃 프로세스 스레드 정상 복구 완료" : "스레드 복구 실패";
    return result;
}

ActuatorResult ProcessActuator::TerminateTargetProcess(uint32_t pid, uint32_t exit_code, std::string_view reason) {
    ActuatorResult result;
    result.pid = pid;

    // 프로세스를 사살하므로 워치독 감시 목록에서 안전하게 제거
    if (watchdog_) {
        std::vector<DWORD> dummy;
        watchdog_->Deregister(pid, dummy);
    }

    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        DWORD err = ::GetLastError();
        result.success = false;
        result.message = "OpenProcess 실패 (오류 코드: " + std::to_string(err) + ")";
        return result;
    }
    Common::UniqueHandle procGuard(hProcess);

    if (::TerminateProcess(hProcess, exit_code)) {
        result.success = true;
        result.message = "프로세스 강제 종료 성공";
        if (!reason.empty()) {
            result.message += " (사유: " + std::string(reason) + ")";
        }
        std::cout << "🛡️ [Actuator] 악성 PID " << pid << " 강제 사살 완료 (" << result.message << ")" << std::endl;
    } else {
        DWORD err = ::GetLastError();
        result.success = false;
        result.message = "TerminateProcess 실패 (오류 코드: " + std::to_string(err) + ")";
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
    std::cout << "[Actuator] 고아 프로세스 PID " << pid << "의 " << thread_ids.size() << "개 스레드 자동 복구 완료" << std::endl;
}

} // namespace Phalanx::Actuator
