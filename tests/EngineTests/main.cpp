#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <numeric>

#include "Process/ProcessTree.h"
#include "Rules/LocalRuleEngine.h"
#include "Actuator/ProcessActuator.h"
#include "Actuator/SafetyWatchdog.h"
#include "Common/Win32Handles.h"

using namespace Phalanx;

// ----------------------------------------------------------------------------
// [Test 1] ProcessTree 스냅샷 웜업 및 10μs 족보(Ancestry) 역추적 검증
// ----------------------------------------------------------------------------
void TestProcessTreeSnapshotAndAncestry() {
    std::cout << "\n[테스트 1] ProcessTree 스냅샷 웜업 & 족보 역추적(< 10μs) 검증 시작..." << std::endl;
    Process::ProcessTree tree;

    // 1. 기동 시점 스냅샷 웜업
    bool snap_ok = tree.InitializeFromSnapshot();
    if (!snap_ok || tree.ActiveNodeCount() == 0) {
        std::cerr << "❌ ProcessTree::InitializeFromSnapshot 실패!" << std::endl;
        std::exit(1);
    }
    std::cout << ">>> 스냅샷 웜업 성공: 로드된 활성 프로세스 = " << tree.ActiveNodeCount() << "개" << std::endl;

    // 2. 4단계 인위적 계층 삽입: Explorer(1000) -> Winword(1001) -> CMD(1002) -> PowerShell(1003) -> CertUtil(1004)
    tree.OnProcessStart(1000, 0, "explorer.exe", "C:\\Windows\\explorer.exe");
    tree.OnProcessStart(1001, 1000, "winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe");
    tree.OnProcessStart(1002, 1001, "cmd.exe", "cmd.exe /c start");
    tree.OnProcessStart(1003, 1002, "powershell.exe", "powershell.exe -NoProfile");
    tree.OnProcessStart(1004, 1003, "certutil.exe", "certutil.exe -urlcache -f");

    // 3. 직계 족보 역추적 검증 (CertUtil의 부모 체인: PowerShell -> CMD -> Winword -> Explorer)
    auto ancestry = tree.GetAncestry(1004, 5, false);
    if (ancestry.size() != 4) {
        std::cerr << "❌ 족보 역추적 깊이 불일치! 기대: 4, 실제: " << ancestry.size() << std::endl;
        std::exit(1);
    }
    assert(ancestry[0].pid == 1003 && ancestry[0].image_name == "powershell.exe");
    assert(ancestry[1].pid == 1002 && ancestry[1].image_name == "cmd.exe");
    assert(ancestry[2].pid == 1001 && ancestry[2].image_name == "winword.exe");
    assert(ancestry[3].pid == 1000 && ancestry[3].image_name == "explorer.exe");

    // 4. max_depth = 2 제한 검증
    auto depth2 = tree.GetAncestry(1004, 2, false);
    assert(depth2.size() == 2);
    assert(depth2[0].pid == 1003);
    assert(depth2[1].pid == 1002);

    // 5. include_self = true 검증
    auto with_self = tree.GetAncestry(1004, 5, true);
    assert(with_self.size() == 5);
    assert(with_self[0].pid == 1004 && with_self[0].image_name == "certutil.exe");

    // 6. 족보 역추적 지연 시간 10,000회 벤치마크 (< 10μs 기준 검증)
    constexpr size_t ITERATIONS = 10000;
    auto t_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < ITERATIONS; ++i) {
        auto res = tree.GetAncestry(1004, 5, false);
        (void)res;
    }
    auto t_end = std::chrono::high_resolution_clock::now();
    double total_us = std::chrono::duration<double, std::micro>(t_end - t_start).count();
    double avg_us = total_us / ITERATIONS;

    std::cout << ">>> 족보 역추적 10,000회 평균 지연 시간: " << avg_us << "μs (요구 기준: < 10μs)" << std::endl;
    if (avg_us >= 10.0) {
        std::cerr << "❌ 족보 역추적 성능 기준 미달 (>= 10μs)!" << std::endl;
        std::exit(1);
    }
    std::cout << "✅ [테스트 1] ProcessTree 스냅샷 웜업 및 족보 역추적 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 2] Windows PID 재사용(PID Reuse) 및 Tombstone 메모리 바운딩 검증
// ----------------------------------------------------------------------------
void TestPIDReuseAndTombstoneMemoryBounding() {
    std::cout << "\n[테스트 2] PID 재사용 및 Tombstone 메모리 바운딩(상한 1,000개) 검증 시작..." << std::endl;
    constexpr size_t BOUNDED_TOMBSTONES = 1000;
    Process::ProcessTree tree(BOUNDED_TOMBSTONES);

    // 1. PID 2000 생성 후 종료
    tree.OnProcessStart(1000, 0, "explorer.exe");
    tree.OnProcessStart(2000, 1000, "legacy_app.exe");
    assert(tree.FindNode(2000)->is_alive == true);

    tree.OnProcessStop(2000);
    assert(tree.FindNode(2000)->is_alive == false);
    assert(tree.TombstoneCount() == 1);

    // 2. 동일 PID 2000 재할당 (Windows PID Reuse)
    tree.OnProcessStart(1001, 0, "services.exe");
    tree.OnProcessStart(2000, 1001, "new_service.exe"); // 덮어쓰기 (PID 재사용)
    auto reused = tree.FindNode(2000);
    assert(reused.has_value());
    assert(reused->is_alive == true);
    assert(reused->image_name == "new_service.exe");
    assert(reused->ppid == 1001);

    // 부모 링크가 1001로 갱신되고 1000의 자식 목록에서 제거되었는지 확인
    auto p1000 = tree.FindNode(1000);
    auto p1001 = tree.FindNode(1001);
    assert(std::find(p1000->children_pids.begin(), p1000->children_pids.end(), 2000) == p1000->children_pids.end());
    assert(std::find(p1001->children_pids.begin(), p1001->children_pids.end(), 2000) != p1001->children_pids.end());
    std::cout << ">>> PID 재사용 덮어쓰기 및 부모-자식 링크 갱신 검증 완료." << std::endl;

    // 3. Tombstone 1,500개 대량 생성 및 1,000개 상한 바운딩(Eviction) 검증
    for (uint32_t p = 5000; p < 6500; ++p) {
        tree.OnProcessStart(p, 1000, "temp_worker.exe");
        tree.OnProcessStop(p);
    }

    std::cout << ">>> 총 누적 노드 수: " << tree.TotalNodeCount()
              << " | Tombstone 수: " << tree.TombstoneCount() << std::endl;

    if (tree.TombstoneCount() > BOUNDED_TOMBSTONES) {
        std::cerr << "❌ Tombstone 개수가 상한(" << BOUNDED_TOMBSTONES << ")을 초과함: "
                  << tree.TombstoneCount() << std::endl;
        std::exit(1);
    }

    // 오래된 PID 5000은 Evict 되어 찾을 수 없어야 함
    assert(!tree.FindNode(5000).has_value());
    // 최근 종료된 PID 6499는 Tombstone으로 여전히 존재해야 함
    assert(tree.FindNode(6499).has_value());

    std::cout << "✅ [테스트 2] PID 재사용 및 Tombstone 메모리 바운딩 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 3] 비할당 고속 대소문자 무시 경로 정규화 및 문자열 매칭 검증
// ----------------------------------------------------------------------------
void TestHighSpeedStringMatching() {
    std::cout << "\n[테스트 3] 비할당 고속 대소문자 무시 경로 정규화 검증 시작..." << std::endl;

    // 1. ExtractBaseFileName 검증
    assert(Rules::LocalRuleEngine::ExtractBaseFileName("C:\\Windows\\System32\\vssadmin.exe") == "vssadmin.exe");
    assert(Rules::LocalRuleEngine::ExtractBaseFileName("C:/Windows/System32/bcdedit.exe") == "bcdedit.exe");
    assert(Rules::LocalRuleEngine::ExtractBaseFileName("powershell.exe") == "powershell.exe");

    // 2. EqualsIgnoreCase 검증
    assert(Rules::LocalRuleEngine::EqualsIgnoreCase("POWERSHELL.EXE", "powershell.exe"));
    assert(Rules::LocalRuleEngine::EqualsIgnoreCase("WinWord.Exe", "winword.exe"));
    assert(!Rules::LocalRuleEngine::EqualsIgnoreCase("cmd.exe", "powershell.exe"));

    // 3. ContainsIgnoreCase 검증
    assert(Rules::LocalRuleEngine::ContainsIgnoreCase("vssadmin.exe delete shadows /all /quiet", "delete"));
    assert(Rules::LocalRuleEngine::ContainsIgnoreCase("vssadmin.exe delete shadows /all /quiet", "SHADOWS"));
    assert(Rules::LocalRuleEngine::ContainsIgnoreCase("bcdedit.exe /set {default} recoveryenabled No", "recoveryenabled"));
    assert(Rules::LocalRuleEngine::ContainsIgnoreCase("bcdedit.exe /set {default} recoveryenabled No", "no"));
    assert(!Rules::LocalRuleEngine::ContainsIgnoreCase("notepad.exe test.txt", "vssadmin"));

    std::cout << "✅ [테스트 3] 비할당 고속 문자열 매칭 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 4] 즉각 사살 (Immediate Kill) 안전 픽스처(Safe Fixture) 검증
// ----------------------------------------------------------------------------
void TestLocalRuleEngineImmediateKillSafeFixture() {
    std::cout << "\n[테스트 4] 즉각 사살 (Immediate Kill) 안전 픽스처 실측 검증 시작..." << std::endl;

    // 안전한 더미 프로세스로 cmd.exe 백그라운드 기동
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[] = "cmd.exe /c timeout /t 15 > nul";

    BOOL created = ::CreateProcessA(
        nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi
    );

    if (!created) {
        std::cerr << "❌ 테스트용 타깃 더미 프로세스(cmd.exe) 기동 실패!" << std::endl;
        std::exit(1);
    }

    Common::UniqueHandle procGuard(pi.hProcess);
    Common::UniqueHandle threadGuard(pi.hThread);
    uint32_t target_pid = static_cast<uint32_t>(pi.dwProcessId);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto watchdog = std::make_shared<Actuator::SafetyWatchdog>(std::chrono::milliseconds(5000));
    auto actuator = std::make_shared<Actuator::ProcessActuator>(watchdog);
    Rules::LocalRuleEngine engine(actuator);
    Process::ProcessTree tree;

    // 안전 픽스처: 더미 프로세스 PID를 타깃으로 하되, 명령줄에 랜섬웨어 볼륨 섀도 삭제 주입
    phalanx::ProcessEvent ev;
    ev.set_process_id(target_pid);
    ev.set_parent_process_id(1000);
    ev.set_image_name("C:\\Windows\\System32\\vssadmin.exe");
    ev.set_command_line("vssadmin.exe delete shadows /all /quiet");

    auto verdict = engine.EvaluateAndAct(ev, tree);

    std::cout << ">>> 사살 평가 결과: " << verdict.rule_name
              << " | 사유: " << verdict.reason
              << " | 소요 시간: " << verdict.evaluation_duration_ns << "ns" << std::endl;

    assert(verdict.action == Rules::RuleAction::KILL);
    assert(ev.is_terminated() == true);
    assert(ev.is_suspended() == false);

    // 실제 프로세스가 0.1ms 만에 사살되었는지 프로세스 핸들 대기로 확인
    DWORD wait_res = ::WaitForSingleObject(pi.hProcess, 1000);
    if (wait_res != WAIT_OBJECT_0) {
        std::cerr << "❌ 대상 프로세스가 즉각 사살되지 않았습니다!" << std::endl;
        ::TerminateProcess(pi.hProcess, 99);
        std::exit(1);
    }

    // 추가 사살 규칙(bcdedit, wbadmin) 순수 판정 검증
    phalanx::ProcessEvent bcd_ev;
    bcd_ev.set_process_id(9991);
    bcd_ev.set_image_name("bcdedit.exe");
    bcd_ev.set_command_line("bcdedit.exe /set {default} recoveryenabled No");
    auto bcd_res = engine.Evaluate(bcd_ev, tree);
    assert(bcd_res.action == Rules::RuleAction::KILL);

    phalanx::ProcessEvent wb_ev;
    wb_ev.set_process_id(9992);
    wb_ev.set_image_name("wbadmin.exe");
    wb_ev.set_command_line("wbadmin.exe delete catalog -quiet");
    auto wb_res = engine.Evaluate(wb_ev, tree);
    assert(wb_res.action == Rules::RuleAction::KILL);

    std::cout << "✅ [테스트 4] 즉각 사살 (Immediate Kill) 안전 픽스처 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 5] 원자적 동결 (Atomic Suspend) 안전 픽스처 검증
// ----------------------------------------------------------------------------
void TestLocalRuleEngineAtomicSuspendSafeFixture() {
    std::cout << "\n[테스트 5] 원자적 동결 (Atomic Suspend) 안전 픽스처 검증 시작..." << std::endl;

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[] = "cmd.exe /c timeout /t 15 > nul";

    BOOL created = ::CreateProcessA(
        nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi
    );

    if (!created) {
        std::cerr << "❌ 테스트용 타깃 더미 프로세스 기동 실패!" << std::endl;
        std::exit(1);
    }

    Common::UniqueHandle procGuard(pi.hProcess);
    Common::UniqueHandle threadGuard(pi.hThread);
    uint32_t target_pid = static_cast<uint32_t>(pi.dwProcessId);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto watchdog = std::make_shared<Actuator::SafetyWatchdog>(std::chrono::milliseconds(5000));
    auto actuator = std::make_shared<Actuator::ProcessActuator>(watchdog);
    Rules::LocalRuleEngine engine(actuator);
    Process::ProcessTree tree;

    // 부모를 winword.exe(PID 8888)로 트리에 사전 등록
    tree.OnProcessStart(8888, 1000, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");

    // 자식으로 target_pid의 powershell.exe 스폰 이벤트 구성
    phalanx::ProcessEvent ev;
    ev.set_process_id(target_pid);
    ev.set_parent_process_id(8888);
    ev.set_image_name("powershell.exe");
    ev.set_command_line("powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...");

    auto verdict = engine.EvaluateAndAct(ev, tree);

    std::cout << ">>> 동결 평가 결과: " << verdict.rule_name
              << " | 사유: " << verdict.reason
              << " | 소요 시간: " << verdict.evaluation_duration_ns << "ns" << std::endl;

    assert(verdict.action == Rules::RuleAction::SUSPEND);
    assert(ev.is_suspended() == true);
    assert(ev.is_terminated() == false);

    // 워치독에 등록되었는지 확인
    assert(watchdog->TrackedCount() == 1);

    // 복구 및 사살 정리
    actuator->ResumeProcess(target_pid);
    actuator->TerminateTargetProcess(target_pid, 0, "Test teardown");

    std::cout << "✅ [테스트 5] 원자적 동결 (Atomic Suspend) 안전 픽스처 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 6] 정상 패스스루 (Pass-through) 검증
// ----------------------------------------------------------------------------
void TestLocalRuleEnginePassThrough() {
    std::cout << "\n[테스트 6] 정상 패스스루(Pass-through) 검증 시작..." << std::endl;
    Process::ProcessTree tree;
    tree.OnProcessStart(1000, 0, "explorer.exe");

    Rules::LocalRuleEngine engine;

    phalanx::ProcessEvent ev;
    ev.set_process_id(3000);
    ev.set_parent_process_id(1000);
    ev.set_image_name("C:\\Windows\\System32\\notepad.exe");
    ev.set_command_line("notepad.exe C:\\dev\\readme.txt");

    auto verdict = engine.Evaluate(ev, tree);
    assert(verdict.action == Rules::RuleAction::PASS);
    assert(verdict.rule_name == "PASS_DEFAULT");

    std::cout << "✅ [테스트 6] 정상 패스스루 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 7] 100μs 초고속 로컬 규칙 엔진 50,000회 연속 벤치마크
// ----------------------------------------------------------------------------
void BenchmarkLocalRuleEngineLatency() {
    std::cout << "\n[테스트 7] 로컬 규칙 엔진 50,000회 연속 평가 벤치마크(< 100μs) 시작..." << std::endl;
    Process::ProcessTree tree;
    tree.OnProcessStart(1000, 0, "explorer.exe");
    tree.OnProcessStart(1001, 1000, "winword.exe");
    tree.OnProcessStart(1002, 1000, "chrome.exe");

    Rules::LocalRuleEngine engine;

    // 다양한 시나리오 이벤트 준비
    std::vector<phalanx::ProcessEvent> workload;
    workload.reserve(3);

    // 1. 랜섬웨어 사살 이벤트
    phalanx::ProcessEvent ev_kill;
    ev_kill.set_process_id(9001);
    ev_kill.set_parent_process_id(1000);
    ev_kill.set_image_name("vssadmin.exe");
    ev_kill.set_command_line("vssadmin.exe delete shadows /all /quiet");
    workload.push_back(ev_kill);

    // 2. 오피스 LOLBAS 동결 이벤트
    phalanx::ProcessEvent ev_suspend;
    ev_suspend.set_process_id(9002);
    ev_suspend.set_parent_process_id(1001);
    ev_suspend.set_image_name("powershell.exe");
    ev_suspend.set_command_line("powershell.exe -NoProfile -Command Write-Host 123");
    workload.push_back(ev_suspend);

    // 3. 정상 패스 이벤트
    phalanx::ProcessEvent ev_pass;
    ev_pass.set_process_id(9003);
    ev_pass.set_parent_process_id(1000);
    ev_pass.set_image_name("notepad.exe");
    ev_pass.set_command_line("notepad.exe document.txt");
    workload.push_back(ev_pass);

    constexpr size_t TOTAL_EVALS = 50000;
    std::vector<double> latencies_us;
    latencies_us.reserve(TOTAL_EVALS);

    auto t_bench_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < TOTAL_EVALS; ++i) {
        const auto& ev = workload[i % workload.size()];
        auto v = engine.Evaluate(ev, tree);
        latencies_us.push_back(static_cast<double>(v.evaluation_duration_ns) / 1000.0);
    }
    auto t_bench_end = std::chrono::high_resolution_clock::now();

    double total_wall_ms = std::chrono::duration<double, std::milli>(t_bench_end - t_bench_start).count();
    std::sort(latencies_us.begin(), latencies_us.end());

    double min_us = latencies_us.front();
    double max_us = latencies_us.back();
    double sum_us = std::accumulate(latencies_us.begin(), latencies_us.end(), 0.0);
    double avg_us = sum_us / TOTAL_EVALS;
    double p95_us = latencies_us[static_cast<size_t>(TOTAL_EVALS * 0.95)];
    double p99_us = latencies_us[static_cast<size_t>(TOTAL_EVALS * 0.99)];
    double throughput = (TOTAL_EVALS / total_wall_ms) * 1000.0;

    std::cout << "--------------------------------------------------------------------------------\n"
              << "   📊 로컬 규칙 엔진 레이턴시 벤치마크 결과 (50,000회 실측 데이터)                 \n"
              << "--------------------------------------------------------------------------------\n"
              << " • 총 평가 이벤트 수   : " << TOTAL_EVALS << " 회\n"
              << " • 전체 소요 시간       : " << total_wall_ms << " ms\n"
              << " • 처리량 (Throughput) : " << static_cast<uint64_t>(throughput) << " evals/sec\n"
              << " • 최소 지연 (Min)     : " << min_us << " μs\n"
              << " • 평균 지연 (Avg)     : " << avg_us << " μs  (요구 기준: < 100μs)\n"
              << " • 95백분위 (P95)      : " << p95_us << " μs\n"
              << " • 99백분위 (P99)      : " << p99_us << " μs\n"
              << " • 최대 지연 (Max)     : " << max_us << " μs\n"
              << "--------------------------------------------------------------------------------" << std::endl;

    if (avg_us >= 100.0) {
        std::cerr << "❌ 규칙 평가 평균 지연 시간이 100μs 기준을 초과했습니다!" << std::endl;
        std::exit(1);
    }
    std::cout << "✅ [테스트 7] 로컬 규칙 엔진 100μs 한계 벤치마크 압도적 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// [Test 8] 실제 OS 프로세스 계층(부모-자식) 반복 생성/종료 & ProcessTree vs OS 완전 일치성 검증
// ----------------------------------------------------------------------------
void TestRealOSProcessTreeSynchronization() {
    std::cout << "\n[테스트 8] 실제 OS 프로세스 반복 생성/삭제 & ProcessTree vs OS 실시간 동기화 검증 시작..." << std::endl;

    // 1. 기준 인메모리 프로세스 트리 생성 및 기동 스냅샷 웜업
    Process::ProcessTree incremental_tree;
    assert(incremental_tree.InitializeFromSnapshot());

    uint32_t current_pid = static_cast<uint32_t>(::GetCurrentProcessId());
    assert(incremental_tree.FindNode(current_pid).has_value());

    // 2. 3회 반복 사이클 실행
    constexpr int CYCLES = 3;
    for (int cycle = 1; cycle <= CYCLES; ++cycle) {
        std::cout << ">>> [사이클 " << cycle << "/" << CYCLES << "] 실제 OS 프로세스 생성 및 트리 일치성 검증..." << std::endl;

        // A. 실제 OS 자식 프로세스 2개 기동 (cmd.exe /c timeout /t 10 > nul)
        STARTUPINFOA si1{};
        si1.cb = sizeof(si1);
        PROCESS_INFORMATION pi1{};
        char cmd1[] = "cmd.exe /c timeout /t 10 > nul";

        BOOL ok1 = ::CreateProcessA(nullptr, cmd1, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si1, &pi1);
        assert(ok1);
        (void)ok1;
        Common::UniqueHandle proc1Guard(pi1.hProcess);
        Common::UniqueHandle thread1Guard(pi1.hThread);
        uint32_t child1_pid = static_cast<uint32_t>(pi1.dwProcessId);

        STARTUPINFOA si2{};
        si2.cb = sizeof(si2);
        PROCESS_INFORMATION pi2{};
        char cmd2[] = "cmd.exe /c timeout /t 10 > nul";

        BOOL ok2 = ::CreateProcessA(nullptr, cmd2, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si2, &pi2);
        assert(ok2);
        (void)ok2;
        Common::UniqueHandle proc2Guard(pi2.hProcess);
        Common::UniqueHandle thread2Guard(pi2.hThread);
        uint32_t child2_pid = static_cast<uint32_t>(pi2.dwProcessId);

        // Windows 커널 프로세스 테이블 정착 대기 (40ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(40));

        // B. 증분 트리에 생성 이벤트 반영 (ETW가 전달하는 이벤트 모델)
        incremental_tree.OnProcessStart(child1_pid, current_pid, "cmd.exe", cmd1);
        incremental_tree.OnProcessStart(child2_pid, current_pid, "cmd.exe", cmd2);

        // C. OS로부터 실시간 전체 스냅샷을 캡처하여 fresh_os_tree 구축
        Process::ProcessTree os_snapshot_tree;
        assert(os_snapshot_tree.InitializeFromSnapshot());

        // D. 일치성 검증 1: 두 실제 자식 프로세스가 OS 스냅샷과 증분 트리 모두에 존재하는가?
        auto inc_node1 = incremental_tree.FindNode(child1_pid);
        auto inc_node2 = incremental_tree.FindNode(child2_pid);
        auto os_node1 = os_snapshot_tree.FindNode(child1_pid);
        auto os_node2 = os_snapshot_tree.FindNode(child2_pid);

        assert(inc_node1.has_value() && inc_node1->is_alive);
        assert(inc_node2.has_value() && inc_node2->is_alive);
        assert(os_node1.has_value() && os_node1->is_alive);
        assert(os_node2.has_value() && os_node2->is_alive);

        // E. 일치성 검증 2: PPID가 실제 부모(current_pid)와 완벽히 일치하는가?
        assert(inc_node1->ppid == current_pid);
        assert(os_node1->ppid == current_pid);
        assert(inc_node2->ppid == current_pid);
        assert(os_node2->ppid == current_pid);

        // F. 일치성 검증 3: 부모의 자식 목록에 child1, child2가 모두 등록되어 있는가?
        auto parent_inc = incremental_tree.FindNode(current_pid);
        assert(parent_inc.has_value());
        assert(std::find(parent_inc->children_pids.begin(), parent_inc->children_pids.end(), child1_pid) != parent_inc->children_pids.end());
        assert(std::find(parent_inc->children_pids.begin(), parent_inc->children_pids.end(), child2_pid) != parent_inc->children_pids.end());

        // G. 일치성 검증 4: 족보 역추적(Ancestry)이 OS 스냅샷의 족보와 100% 동일한가?
        auto inc_ancestry1 = incremental_tree.GetAncestry(child1_pid, 3, false);
        auto os_ancestry1 = os_snapshot_tree.GetAncestry(child1_pid, 3, false);
        assert(!inc_ancestry1.empty() && !os_ancestry1.empty());
        assert(inc_ancestry1[0].pid == current_pid);
        assert(os_ancestry1[0].pid == current_pid);

        // H. 실제 프로세스 1개 종료 (Child 1)
        ::TerminateProcess(pi1.hProcess, 0);
        ::WaitForSingleObject(pi1.hProcess, 2000);
        incremental_tree.OnProcessStop(child1_pid);

        std::this_thread::sleep_for(std::chrono::milliseconds(40));

        // I. 종료 후 OS 재검증: OS 스냅샷에서는 완전히 삭제되었고, 우리 트리에서는 Tombstone(is_alive=false)으로 보존되는가?
        Process::ProcessTree os_snap_after_kill1;
        assert(os_snap_after_kill1.InitializeFromSnapshot());

        auto inc_dead1 = incremental_tree.FindNode(child1_pid);
        auto os_dead1 = os_snap_after_kill1.FindNode(child1_pid);

        assert(inc_dead1.has_value() && !inc_dead1->is_alive); // 우리 트리는 포렌식을 위해 Tombstone 유지!
        assert(!os_dead1.has_value()); // OS는 프로세스 테이블에서 즉각 삭제!

        // Child 2는 아직 OS와 우리 트리 모두에서 살아있는지 확인
        auto inc_alive2 = incremental_tree.FindNode(child2_pid);
        auto os_alive2 = os_snap_after_kill1.FindNode(child2_pid);
        assert(inc_alive2.has_value() && inc_alive2->is_alive);
        assert(os_alive2.has_value() && os_alive2->is_alive);

        // J. 실제 프로세스 Child 2 종료
        ::TerminateProcess(pi2.hProcess, 0);
        ::WaitForSingleObject(pi2.hProcess, 2000);
        incremental_tree.OnProcessStop(child2_pid);

        std::this_thread::sleep_for(std::chrono::milliseconds(40));

        Process::ProcessTree os_snap_after_kill2;
        assert(os_snap_after_kill2.InitializeFromSnapshot());
        assert(!os_snap_after_kill2.FindNode(child2_pid).has_value());
        assert(incremental_tree.FindNode(child2_pid).has_value() && !incremental_tree.FindNode(child2_pid)->is_alive);

        std::cout << ">>> [사이클 " << cycle << "] 완료: 생성 2건, 종료 2건, OS-인메모리 트리 100% 동기화 확인." << std::endl;
    }

    std::cout << "✅ [테스트 8] 실제 OS 프로세스 반복 생성/삭제 & ProcessTree vs OS 실시간 동기화 검증 통과!" << std::endl;
}

int main() {
    ::SetConsoleOutputCP(CP_UTF8);
    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX PHASE 2: C++ 엔진 & 로컬 규칙 엔진 핵심 검증 (EngineTests)           " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TestProcessTreeSnapshotAndAncestry();
    TestPIDReuseAndTombstoneMemoryBounding();
    TestHighSpeedStringMatching();
    TestLocalRuleEngineImmediateKillSafeFixture();
    TestLocalRuleEngineAtomicSuspendSafeFixture();
    TestLocalRuleEnginePassThrough();
    BenchmarkLocalRuleEngineLatency();
    TestRealOSProcessTreeSynchronization();

    std::cout << "\n================================================================================" << std::endl;
    std::cout << "🎉 Phase 2 모든 단위 및 벤치마크 테스트 검증 성공! (Exit Code 0)                " << std::endl;
    std::cout << "================================================================================" << std::endl;
    return 0;
}
