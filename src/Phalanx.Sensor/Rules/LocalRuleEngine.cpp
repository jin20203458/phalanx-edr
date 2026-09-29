#include "LocalRuleEngine.h"
#include <chrono>
#include <cctype>

namespace Phalanx::Rules {

LocalRuleEngine::LocalRuleEngine(std::shared_ptr<Actuator::ProcessActuator> actuator)
    : actuator_(std::move(actuator)) {
}

std::string_view LocalRuleEngine::ExtractBaseFileName(std::string_view path) noexcept {
    size_t idx = path.find_last_of("\\/");
    if (idx == std::string_view::npos) {
        return path;
    }
    return path.substr(idx + 1);
}

bool LocalRuleEngine::EqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool LocalRuleEngine::ContainsIgnoreCase(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    size_t max_start = haystack.size() - needle.size();
    for (size_t i = 0; i <= max_start; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

RuleVerdict LocalRuleEngine::Evaluate(const phalanx::ProcessEvent& event, const Process::ProcessTree& tree) const {
    auto t_start = std::chrono::high_resolution_clock::now();
    RuleVerdict verdict;

    std::string_view base_img = ExtractBaseFileName(event.image_name());
    std::string_view cmd = event.command_line();

    // ------------------------------------------------------------------------
    // [경로 1] 즉각 사살 (Immediate Kill) 규칙: 랜섬웨어 시스템 복구 파괴 행위
    // ------------------------------------------------------------------------
    // 1.1 vssadmin.exe delete shadows
    if (EqualsIgnoreCase(base_img, "vssadmin.exe") || ContainsIgnoreCase(cmd, "vssadmin")) {
        if (ContainsIgnoreCase(cmd, "delete") && ContainsIgnoreCase(cmd, "shadows")) {
            verdict.action = RuleAction::KILL;
            verdict.rule_name = "KILL_VSSADMIN_DELETE_SHADOWS";
            verdict.reason = "Ransomware shadow copy deletion detected (vssadmin delete shadows)";
        }
    }

    // 1.2 bcdedit.exe recoveryenabled No / ignoreallfailures
    if (verdict.action == RuleAction::PASS &&
        (EqualsIgnoreCase(base_img, "bcdedit.exe") || ContainsIgnoreCase(cmd, "bcdedit"))) {
        if ((ContainsIgnoreCase(cmd, "recoveryenabled") && ContainsIgnoreCase(cmd, "no")) ||
            ContainsIgnoreCase(cmd, "ignoreallfailures")) {
            verdict.action = RuleAction::KILL;
            verdict.rule_name = "KILL_BCDEDIT_DISABLE_RECOVERY";
            verdict.reason = "Ransomware recovery disabling detected (bcdedit recoveryenabled No)";
        }
    }

    // 1.3 wbadmin.exe delete catalog / delete systemstatebackup
    if (verdict.action == RuleAction::PASS &&
        (EqualsIgnoreCase(base_img, "wbadmin.exe") || ContainsIgnoreCase(cmd, "wbadmin"))) {
        if (ContainsIgnoreCase(cmd, "delete") &&
            (ContainsIgnoreCase(cmd, "catalog") || ContainsIgnoreCase(cmd, "systemstatebackup"))) {
            verdict.action = RuleAction::KILL;
            verdict.rule_name = "KILL_WBADMIN_DELETE_BACKUP";
            verdict.reason = "Backup deletion detected (wbadmin delete catalog)";
        }
    }

    // 사살 규칙 매칭 완료 시 조기 탈출
    if (verdict.action == RuleAction::KILL) {
        auto t_end = std::chrono::high_resolution_clock::now();
        verdict.evaluation_duration_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
        return verdict;
    }

    // ------------------------------------------------------------------------
    // [경로 2] 원자적 동결 (Atomic Suspend) 규칙: 오피스/브라우저의 LOLBAS 스폰
    // ------------------------------------------------------------------------
    bool is_lolbas_child =
        EqualsIgnoreCase(base_img, "powershell.exe") ||
        EqualsIgnoreCase(base_img, "cmd.exe") ||
        EqualsIgnoreCase(base_img, "certutil.exe") ||
        EqualsIgnoreCase(base_img, "mshta.exe") ||
        EqualsIgnoreCase(base_img, "wscript.exe") ||
        EqualsIgnoreCase(base_img, "cscript.exe");

    if (is_lolbas_child && event.parent_process_id() != 0) {
        auto parent_node = tree.FindNode(event.parent_process_id());
        if (parent_node.has_value()) {
            std::string_view parent_base = ExtractBaseFileName(parent_node->image_name);
            bool is_office_browser_parent =
                EqualsIgnoreCase(parent_base, "winword.exe") ||
                EqualsIgnoreCase(parent_base, "excel.exe") ||
                EqualsIgnoreCase(parent_base, "powerpnt.exe") ||
                EqualsIgnoreCase(parent_base, "outlook.exe") ||
                EqualsIgnoreCase(parent_base, "msedge.exe") ||
                EqualsIgnoreCase(parent_base, "chrome.exe");

            if (is_office_browser_parent) {
                verdict.action = RuleAction::SUSPEND;
                verdict.rule_name = "SUSPEND_OFFICE_LOLBAS_SPAWN";
                verdict.reason = "Suspicious LOLBAS child spawned by Office/Browser: " +
                                 std::string(parent_base) + " -> " + std::string(base_img);
            }
        }
    }

    // ------------------------------------------------------------------------
    // [경로 3] 정상 패스스루
    // ------------------------------------------------------------------------
    if (verdict.action == RuleAction::PASS) {
        verdict.rule_name = "PASS_DEFAULT";
        verdict.reason = "Clean execution path";
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    verdict.evaluation_duration_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count());
    return verdict;
}

RuleVerdict LocalRuleEngine::EvaluateAndAct(phalanx::ProcessEvent& event, const Process::ProcessTree& tree) {
    RuleVerdict verdict = Evaluate(event, tree);

    total_latency_ns_.fetch_add(verdict.evaluation_duration_ns, std::memory_order_relaxed);
    total_evaluated_.fetch_add(1, std::memory_order_relaxed);

    if (verdict.action == RuleAction::KILL) {
        total_killed_.fetch_add(1, std::memory_order_relaxed);
        event.set_is_terminated(true);
        event.set_is_suspended(false);
        if (actuator_) {
            actuator_->TerminateTargetProcess(event.process_id(), 1, verdict.reason);
        }
    } else if (verdict.action == RuleAction::SUSPEND) {
        total_suspended_.fetch_add(1, std::memory_order_relaxed);
        event.set_is_suspended(true);
        event.set_is_terminated(false);
        if (actuator_) {
            actuator_->SuspendProcess(event.process_id());
        }
    } else {
        total_passed_.fetch_add(1, std::memory_order_relaxed);
        event.set_is_suspended(false);
        event.set_is_terminated(false);
    }

    return verdict;
}

RuleEngineMetrics LocalRuleEngine::GetMetrics() const {
    RuleEngineMetrics m;
    m.total_evaluated = total_evaluated_.load(std::memory_order_relaxed);
    m.total_killed = total_killed_.load(std::memory_order_relaxed);
    m.total_suspended = total_suspended_.load(std::memory_order_relaxed);
    m.total_passed = total_passed_.load(std::memory_order_relaxed);
    uint64_t lat = total_latency_ns_.load(std::memory_order_relaxed);
    if (m.total_evaluated > 0) {
        m.avg_eval_latency_us = static_cast<double>(lat) / (static_cast<double>(m.total_evaluated) * 1000.0);
    }
    return m;
}

} // namespace Phalanx::Rules
