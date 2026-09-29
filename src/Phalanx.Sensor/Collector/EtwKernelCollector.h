#pragma once

#include <memory>
#include <string>
#include <functional>
#include "../Queue/DoubleBufferedSwapQueue.h"
#include "../Process/ProcessTree.h"
#include "../Rules/LocalRuleEngine.h"
#include "phalanx.pb.h"

namespace Phalanx::Collector {

// 프로세스 이벤트 수신 시 호출될 옵저버 콜백 타입 정의
using ProcessEventCallback = std::function<void(const phalanx::ProcessEvent&)>;

/**
 * @brief Microsoft krabs-etw 라이브러리 기반 실시간 ETW 커널 프로세스 이벤트 수집기.
 *
 * Microsoft-Windows-Kernel-Process 매니페스트 프로바이더를 실시간 구독하여,
 * ProcessStart(이벤트 ID 1) 및 ProcessStop(이벤트 ID 2) 이벤트를 블로킹 없이
 * 마이크로초 단위 속도로 파싱하고 ProcessTree 갱신 및 LocalRuleEngine 평가를 거쳐
 * DoubleBufferedSwapQueue로 즉각 푸시합니다.
 */
class EtwKernelCollector {
public:
    explicit EtwKernelCollector(
        std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue,
        std::shared_ptr<Process::ProcessTree> tree = nullptr,
        std::shared_ptr<Rules::LocalRuleEngine> rule_engine = nullptr);
    ~EtwKernelCollector();

    EtwKernelCollector(const EtwKernelCollector&) = delete;
    EtwKernelCollector& operator=(const EtwKernelCollector&) = delete;

    void SetProcessTree(std::shared_ptr<Process::ProcessTree> tree);
    void SetRuleEngine(std::shared_ptr<Rules::LocalRuleEngine> rule_engine);

    /**
     * @brief 실시간 콘솔 출력 또는 1차 반사신경 진단을 위한 옵저버 콜백 등록
     */
    void SetProcessObserver(ProcessEventCallback callback);

    /**
     * @brief 전용 백그라운드 워커 스레드에서 ETW 트레이스 세션을 시작
     */
    bool Start();

    /**
     * @brief ETW 트레이스 세션을 정지하고 워커 스레드를 안전하게 조인
     */
    void Stop();

    // 트레이스 세션 실행 여부 반환
    [[nodiscard]] bool IsRunning() const noexcept;

    // 수집된 총 이벤트 수 반환
    [[nodiscard]] size_t EventsCaptured() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Phalanx::Collector
