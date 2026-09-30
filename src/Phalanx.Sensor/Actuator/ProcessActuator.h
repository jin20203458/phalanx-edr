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
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <atomic>
#include <chrono>
#include "SafetyWatchdog.h"
#include "../Common/Win32Handles.h"

namespace Phalanx::Actuator {

// 프로세스 동결 집행 방식
enum class FreezeMethod {
    UNKNOWN = 0,
    ATOMIC_NT,       // 1순위: ntdll!NtSuspendProcess 원자적 동결 (10~20μs)
    THREAD_SNAPSHOT  // 2순위: Toolhelp32 + SuspendThread 스레드 순회 폴백
};

// 프로세스 조작(동결/해제/사살) 결과 구조체
struct ActuatorResult {
    bool success{false};
    uint32_t pid{0};
    std::string message;
    uint32_t threads_affected{0};
    FreezeMethod method{FreezeMethod::UNKNOWN};
    uint64_t elapsed_microseconds{0}; // 동결 또는 조작에 소요된 시간(마이크로초)
};

/**
 * @brief Win32 / Native NT 기반 초고속 프로세스 동결(Freeze) 및 사살(Termination) 액추에이터.
 *
 * Phase 1.5 2중 방어선(Two-Tier Architecture):
 *  1순위: ntdll.dll의 NtSuspendProcess를 호출하여 프로세스 전체를 10~20μs 이내에 원자적으로 동결.
 *         (동결 도중 스레드 급조 탈출 레이스 컨디션 원천 차단)
 *  2순위: NtSuspendProcess 실패 또는 환경 비호환 시 CreateToolhelp32Snapshot + SuspendThread로 우아하게 자동 폴백.
 */
class ProcessActuator {
public:
    explicit ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog = nullptr);
    ~ProcessActuator() = default;

    /**
     * @brief 타깃 프로세스를 원자적으로 초고속 동결(Suspend)하며, 실패 시 스레드 순회 방식으로 자동 폴백
     */
    ActuatorResult SuspendProcess(uint32_t pid);

    /**
     * @brief 동결된 프로세스를 정상 상태로 복구(Resume)하며, 1순위 NtResumeProcess 실패 시 스레드 순회 폴백
     */
    ActuatorResult ResumeProcess(uint32_t pid);

    /**
     * @brief Win32 TerminateProcess API를 호출하여 악성 프로세스를 즉각 강제 종료
     */
    ActuatorResult TerminateTargetProcess(uint32_t pid, uint32_t exit_code = 1, std::string_view reason = "");

    /**
     * @brief 동결된 프로세스의 워치독 안전 타임아웃 1회 연장 (최대 1회 제한)
     */
    bool ExtendTimeout(uint32_t pid, std::chrono::milliseconds extend_by = std::chrono::milliseconds(30000));

    /**
     * @brief Toolhelp32 스냅샷을 사용하여 특정 PID에 속한 모든 스레드 ID 목록을 고속 열거
     */
    static std::vector<DWORD> EnumerateProcessThreads(uint32_t pid);

    /**
     * @brief 결함 주입(Fault Injection) 테스트를 위해 1순위 NtSuspendProcess를 의도적으로 건너뛰고 2순위 폴백을 강제
     */
    void SetForceFallback(bool force) noexcept {
        force_fallback_.store(force, std::memory_order_release);
    }

    [[nodiscard]] bool IsForceFallback() const noexcept {
        return force_fallback_.load(std::memory_order_acquire);
    }

    // 연동된 세이프티 워치독 인스턴스 반환
    [[nodiscard]] std::shared_ptr<SafetyWatchdog> Watchdog() const noexcept {
        return watchdog_;
    }

private:
    // ntdll 미공개 API 함수 시그니처 정의
    using pfnNtSuspendProcess = LONG(NTAPI*)(HANDLE ProcessHandle);
    using pfnNtResumeProcess = LONG(NTAPI*)(HANDLE ProcessHandle);

    // 1순위: ntdll!NtSuspendProcess 원자적 동결
    ActuatorResult SuspendProcessAtomic(uint32_t pid, HANDLE hProcess);

    // 2순위: Toolhelp32 + SuspendThread 우아한 폴백
    ActuatorResult SuspendProcessFallback(uint32_t pid);

    // 1순위: ntdll!NtResumeProcess 원자적 복구
    ActuatorResult ResumeProcessAtomic(uint32_t pid, HANDLE hProcess);

    // 2순위: ResumeThread 스레드별 복구 폴백
    ActuatorResult ResumeProcessFallback(uint32_t pid, const std::vector<DWORD>& thread_ids);

    // 워치독 만료 시 자동 동결 해제를 처리하는 내부 핸들러
    void HandleAutoResume(uint32_t pid, const std::vector<DWORD>& thread_ids);

    std::shared_ptr<SafetyWatchdog> watchdog_;
    std::atomic<bool> force_fallback_{false};

    // ntdll 동적 함수 포인터 (프로세스 기동 시 1회 로드 및 캐시)
    pfnNtSuspendProcess nt_suspend_process_{nullptr};
    pfnNtResumeProcess nt_resume_process_{nullptr};
};

} // namespace Phalanx::Actuator
