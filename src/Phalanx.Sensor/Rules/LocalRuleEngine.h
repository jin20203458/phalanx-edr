#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <atomic>
#include "../Process/ProcessTree.h"
#include "../Actuator/ProcessActuator.h"
#include "phalanx.pb.h"

namespace Phalanx::Rules {

enum class RuleAction {
    PASS = 0,
    SUSPEND = 1,
    KILL = 2
};

struct RuleVerdict {
    RuleAction action{RuleAction::PASS};
    std::string rule_name;
    std::string reason;
    uint64_t evaluation_duration_ns{0};
};

struct RuleEngineMetrics {
    uint64_t total_evaluated{0};
    uint64_t total_killed{0};
    uint64_t total_suspended{0};
    uint64_t total_passed{0};
    double avg_eval_latency_us{0.0};
};

/**
 * @brief 100μs 초고속 로컬 결정론적 규칙 평가 엔진.
 *
 * 평가 경로:
 *  1. 즉각 사살 (Immediate Kill): 볼륨 섀도 복사본 삭제 및 복구 파괴 (0.1ms 사살)
 *  2. 원자적 동결 (Atomic Suspend): 오피스/브라우저 프로세스의 LOLBAS 자식 스폰 (24μs 동결 + 워치독)
 *  3. 정상 패스스루 (Pass): 통과
 */
class LocalRuleEngine {
public:
    explicit LocalRuleEngine(std::shared_ptr<Actuator::ProcessActuator> actuator = nullptr);
    ~LocalRuleEngine() = default;

    /**
     * @brief 프로세스 이벤트를 순수 평가하여 판정(Verdict)만 반환 (OS 액추에이터 미호출, 벤치마크 및 테스트용).
     */
    [[nodiscard]] RuleVerdict Evaluate(const phalanx::ProcessEvent& event, const Process::ProcessTree& tree) const;

    /**
     * @brief 프로세스 이벤트를 평가하고 판정에 따라 액추에이터 조치(사살/동결)를 즉각 집행하며 이벤트 플래그를 갱신.
     */
    RuleVerdict EvaluateAndAct(phalanx::ProcessEvent& event, const Process::ProcessTree& tree);

    /**
     * @brief 실시간 누적 통계 지표 조회.
     */
    [[nodiscard]] RuleEngineMetrics GetMetrics() const;

    /**
     * @brief 액추에이터 주입/교체 (단위 테스트용)
     */
    void SetActuator(std::shared_ptr<Actuator::ProcessActuator> actuator) noexcept {
        actuator_ = std::move(actuator);
    }

    // 고속 비할당 문자열 정규화 및 매칭 헬퍼 (테스트 및 내부 공용)
    static std::string_view ExtractBaseFileName(std::string_view path) noexcept;
    static bool EqualsIgnoreCase(std::string_view a, std::string_view b) noexcept;
    static bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle) noexcept;

private:
    std::shared_ptr<Actuator::ProcessActuator> actuator_;

    mutable std::atomic<uint64_t> total_evaluated_{0};
    mutable std::atomic<uint64_t> total_killed_{0};
    mutable std::atomic<uint64_t> total_suspended_{0};
    mutable std::atomic<uint64_t> total_passed_{0};
    mutable std::atomic<uint64_t> total_latency_ns_{0};
};

} // namespace Phalanx::Rules
