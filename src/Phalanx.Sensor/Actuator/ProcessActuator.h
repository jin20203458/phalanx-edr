#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include "SafetyWatchdog.h"

namespace Phalanx::Actuator {

// 프로세스 조작(동결/해제/사살) 결과 구조체
struct ActuatorResult {
    bool success{false};
    uint32_t pid{0};
    std::string message;
    uint32_t threads_affected{0};
};

/**
 * @brief Win32 기반 고속 프로세스 실행 중단 및 사살(Termination) 액추에이터.
 *
 * 위협 의심 프로세스 감지 시 Win32 SuspendThread를 호출하여 20ms 이내에 조기 실행을 차단(Freeze)하고,
 * 악성 판정 시 TerminateProcess를 통해 즉각 사살합니다.
 */
class ProcessActuator {
public:
    explicit ProcessActuator(std::shared_ptr<SafetyWatchdog> watchdog = nullptr);
    ~ProcessActuator() = default;

    /**
     * @brief 타깃 프로세스의 모든 실행 스레드를 20ms 이내에 즉각 동결(Suspend)
     */
    ActuatorResult SuspendProcess(uint32_t pid);

    /**
     * @brief 동결된 프로세스의 스레드들을 정상 상태로 복구(Resume)
     */
    ActuatorResult ResumeProcess(uint32_t pid);

    /**
     * @brief Win32 TerminateProcess API를 호출하여 악성 프로세스를 즉각 강제 종료
     */
    ActuatorResult TerminateTargetProcess(uint32_t pid, uint32_t exit_code = 1, std::string_view reason = "");

    /**
     * @brief Toolhelp32 스냅샷을 사용하여 특정 PID에 속한 모든 스레드 ID 목록을 고속 열거
     */
    static std::vector<DWORD> EnumerateProcessThreads(uint32_t pid);

    // 연동된 세이프티 워치독 인스턴스 반환
    [[nodiscard]] std::shared_ptr<SafetyWatchdog> Watchdog() const noexcept {
        return watchdog_;
    }

private:
    // 워치독 만료 시 자동 동결 해제를 처리하는 내부 핸들러
    void HandleAutoResume(uint32_t pid, const std::vector<DWORD>& thread_ids);

    std::shared_ptr<SafetyWatchdog> watchdog_;
};

} // namespace Phalanx::Actuator
