#include "ProcessActuator.h"
#include "../Common/Win32Handles.h"
#include <tlhelp32.h>
#include <iostream>
#include <chrono>

namespace Phalanx::Actuator {

ProcessActuator::ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog)
    : watchdog_(std::move(watchdog)) {
    // ntdll.dll 에서 NtSuspendProcess 및 NtResumeProcess 미공개 API 동적 바인딩
    HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        nt_suspend_process_ = reinterpret_cast<pfnNtSuspendProcess>(::GetProcAddress(hNtdll, "NtSuspendProcess"));
        nt_resume_process_ = reinterpret_cast<pfnNtResumeProcess>(::GetProcAddress(hNtdll, "NtResumeProcess"));
    }

    if (watchdog_) {
        // 워치독 타임아웃 만료 시 호출될 자동 복구 핸들러 등록
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

ActuatorResult ProcessActuator::SuspendProcessAtomic(uint32_t pid, HANDLE hProcess) {
    auto start_time = std::chrono::steady_clock::now();
    ActuatorResult result;
    result.pid = pid;

    LONG status = nt_suspend_process_(hProcess);
    auto end_time = std::chrono::steady_clock::now();
    result.elapsed_microseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()
    );

    if (status >= 0) { // NT_SUCCESS(status) 성공 상태 확인
        result.success = true;
        result.method = FreezeMethod::ATOMIC_NT;
        result.message = "NtSuspendProcess 원자적 동결 완료 (" + std::to_string(result.elapsed_microseconds) + "μs 소요)";
        
        // 워치독에 등록 (스레드 목록은 비어 있어도 원자적 복구 수행 가능)
        if (watchdog_) {
            watchdog_->RegisterSuspended(pid, {});
        }
        return result;
    }

    result.success = false;
    result.message = "NtSuspendProcess 실패 (NTSTATUS: " + std::to_string(status) + ")";
    return result;
}

ActuatorResult ProcessActuator::SuspendProcessFallback(uint32_t pid) {
    auto start_time = std::chrono::steady_clock::now();
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

    auto end_time = std::chrono::steady_clock::now();
    result.elapsed_microseconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()
    );

    if (suspended_tids.empty()) {
        result.success = false;
        result.message = "타깃 프로세스의 스레드를 동결하지 못했습니다 (권한 부족 또는 종료됨)";
        return result;
    }

    result.threads_affected = static_cast<uint32_t>(suspended_tids.size());
    result.success = true;
    result.method = FreezeMethod::THREAD_SNAPSHOT;
    result.message = "Toolhelp32 스레드 순회 동결 완료 (" + std::to_string(result.threads_affected) + "개 스레드, " +
                     std::to_string(result.elapsed_microseconds) + "μs 소요)";

    // 동결 성공 시 OS 로더 락 데드락 방지를 위해 세이프티 워치독에 등록
    if (watchdog_) {
        watchdog_->RegisterSuspended(pid, std::move(suspended_tids));
    }

    return result;
}

ActuatorResult ProcessActuator::SuspendProcess(uint32_t pid) {
    // 1순위: ntdll!NtSuspendProcess 원자적 동결 시도 (10~20μs 목표, 강제 폴백 모드가 아닐 때)
    if (!force_fallback_.load(std::memory_order_acquire) && nt_suspend_process_) {
        HANDLE hProcess = ::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (hProcess) {
            Common::UniqueHandle procGuard(hProcess);
            auto atomic_result = SuspendProcessAtomic(pid, hProcess);
            if (atomic_result.success) {
                return atomic_result;
            }
            std::cerr << "⚠️ [Actuator] 1순위 NtSuspendProcess 실패: " << atomic_result.message
                      << " ➔ 2순위 Toolhelp32 폴백 가동!" << std::endl;
        } else {
            std::cerr << "⚠️ [Actuator] PROCESS_SUSPEND_RESUME 권한으로 프로세스 열기 실패 (PID: " << pid
                      << ") ➔ 2순위 Toolhelp32 폴백 가동!" << std::endl;
        }
    }

    // 2순위: Toolhelp32 + SuspendThread 우아한 자동 폴백 (Graceful Fallback)
    return SuspendProcessFallback(pid);
}

ActuatorResult ProcessActuator::ResumeProcessAtomic(uint32_t pid, HANDLE hProcess) {
    ActuatorResult result;
    result.pid = pid;

    LONG status = nt_resume_process_(hProcess);
    if (status >= 0) {
        result.success = true;
        result.method = FreezeMethod::ATOMIC_NT;
        result.message = "NtResumeProcess 원자적 복구 완료";
        return result;
    }

    result.success = false;
    result.message = "NtResumeProcess 실패 (NTSTATUS: " + std::to_string(status) + ")";
    return result;
}

ActuatorResult ProcessActuator::ResumeProcessFallback(uint32_t pid, const std::vector<DWORD>& thread_ids) {
    ActuatorResult result;
    result.pid = pid;

    std::vector<DWORD> tids = thread_ids;
    if (tids.empty()) {
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
    result.method = FreezeMethod::THREAD_SNAPSHOT;
    result.message = result.success ? "스레드 순회 복구 완료 (" + std::to_string(resumed_count) + "개 스레드)"
                                    : "스레드 복구 실패 (스레드를 열 수 없음)";
    return result;
}

ActuatorResult ProcessActuator::ResumeProcess(uint32_t pid) {
    std::vector<DWORD> tids;
    if (watchdog_) {
        watchdog_->Deregister(pid, tids);
    }

    // 1순위: ntdll!NtResumeProcess 원자적 복구 시도 (강제 폴백 모드가 아닐 때)
    if (!force_fallback_.load(std::memory_order_acquire) && nt_resume_process_) {
        HANDLE hProcess = ::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (hProcess) {
            Common::UniqueHandle procGuard(hProcess);
            auto atomic_res = ResumeProcessAtomic(pid, hProcess);
            if (atomic_res.success) {
                return atomic_res;
            }
        }
    }

    // 2순위: 개별 스레드 순회 복구 폴백
    return ResumeProcessFallback(pid, tids);
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
    // 1순위: NtResumeProcess 시도
    bool atomic_succeeded = false;
    if (nt_resume_process_) {
        HANDLE hProcess = ::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (hProcess) {
            Common::UniqueHandle procGuard(hProcess);
            if (nt_resume_process_(hProcess) >= 0) {
                atomic_succeeded = true;
                std::cout << "[Actuator] 고아 프로세스 PID " << pid << " NtResumeProcess 원자적 자동 복구 완료" << std::endl;
            }
        }
    }

    // 2순위: 실패 또는 스레드 목록이 있는 경우 개별 스레드 복구 폴백
    if (!atomic_succeeded) {
        std::vector<DWORD> tids = thread_ids;
        if (tids.empty()) {
            tids = EnumerateProcessThreads(pid);
        }
        for (DWORD tid : tids) {
            HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
            if (hThread) {
                Common::UniqueHandle guard(hThread);
                ::ResumeThread(hThread);
            }
        }
        std::cout << "[Actuator] 고아 프로세스 PID " << pid << "의 " << tids.size() << "개 스레드 자동 복구 완료" << std::endl;
    }
}

bool ProcessActuator::ExtendTimeout(uint32_t pid, std::chrono::milliseconds extend_by) {
    if (watchdog_) {
        return watchdog_->ExtendTimeout(pid, extend_by);
    }
    return false;
}

} // namespace Phalanx::Actuator
