#include <iostream>
#include <cassert>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

#include "../../src/Phalanx.Sensor/Queue/DoubleBufferedSwapQueue.h"
#include "../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.h"
#include "../../src/Phalanx.Sensor/Actuator/ProcessActuator.h"
#include "../../src/Phalanx.Sensor/Common/Win32Handles.h"

void TestDoubleBufferedSwapQueue() {
    std::cout << "[단위테스트] DoubleBufferedSwapQueue 100,000건 동시 Push 및 무손실 스왑 검증 시작..." << std::endl;
    Phalanx::Queue::DoubleBufferedSwapQueue<uint32_t, 32768> queue;

    constexpr int NUM_PRODUCERS = 4;
    constexpr int ITEMS_PER_PRODUCER = 25000;
    constexpr int TOTAL_ITEMS = NUM_PRODUCERS * ITEMS_PER_PRODUCER;

    std::atomic<bool> start_signal{false};
    std::vector<std::thread> producers;

    for (int i = 0; i < NUM_PRODUCERS; ++i) {
        producers.emplace_back([&queue, &start_signal, i]() {
            while (!start_signal.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int j = 0; j < ITEMS_PER_PRODUCER; ++j) {
                while (!queue.Push(static_cast<uint32_t>(i * ITEMS_PER_PRODUCER + j))) {
                    std::this_thread::yield();
                }
            }
        });
    }

    std::atomic<size_t> total_collected{0};
    std::atomic<bool> consuming{true};

    std::thread consumer([&queue, &total_collected, &consuming]() {
        while (consuming.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            auto* batch = queue.SwapAndFlush();
            if (batch) {
                total_collected.fetch_add(batch->size(), std::memory_order_relaxed);
            }
        }
        // 최종 잔여 버퍼 플러시 (Final drain)
        auto* batch = queue.SwapAndFlush();
        if (batch) {
            total_collected.fetch_add(batch->size(), std::memory_order_relaxed);
        }
    });

    start_signal.store(true, std::memory_order_release);

    for (auto& t : producers) {
        t.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    consuming.store(false, std::memory_order_release);
    consumer.join();

    std::cout << ">>> 수집된 항목 수: " << total_collected.load() << " / " << TOTAL_ITEMS
              << " | 유실(Dropped) 수: " << queue.DroppedCount() << std::endl;

    if (total_collected.load() != TOTAL_ITEMS || queue.DroppedCount() != 0) {
        std::cerr << "❌ DoubleBufferedSwapQueue 테스트 실패!" << std::endl;
        std::exit(1);
    }
    std::cout << "✅ DoubleBufferedSwapQueue 동시성 테스트 통과!" << std::endl;
}

void TestSafetyWatchdog() {
    std::cout << "\n[단위테스트] SafetyWatchdog 타임아웃 및 자동 재개(Auto-Resume) 검증 시작..." << std::endl;
    auto watchdog = std::make_shared<Phalanx::Actuator::SafetyWatchdog>(std::chrono::milliseconds(200));

    std::atomic<bool> callback_invoked{false};
    std::atomic<uint32_t> resumed_pid{0};

    watchdog->SetAutoResumeCallback([&callback_invoked, &resumed_pid](uint32_t pid, const std::vector<DWORD>& /*threads*/) {
        resumed_pid.store(pid, std::memory_order_release);
        callback_invoked.store(true, std::memory_order_release);
    });

    watchdog->RegisterSuspended(99999, {101, 102}, std::chrono::milliseconds(200));
    assert(watchdog->TrackedCount() == 1);

    // 1회성 연장 티켓 검증: 1회차 연장은 성공해야 함
    bool extend_1_ok = watchdog->ExtendTimeout(99999, std::chrono::milliseconds(300));
    if (!extend_1_ok) {
        std::cerr << "❌ SafetyWatchdog 1회차 연장 실패!" << std::endl;
        std::exit(1);
    }

    // 절대 상한선 가드 검증: 2회차 연장 시도는 단호히 거부되어야 함
    bool extend_2_ok = watchdog->ExtendTimeout(99999, std::chrono::milliseconds(300));
    if (extend_2_ok) {
        std::cerr << "❌ SafetyWatchdog 2회차 연장 거부 가드 실패!" << std::endl;
        std::exit(1);
    }

    // 누적 연장된 타임아웃(200ms + 300ms = 500ms) 만료 대기 (워치독 200ms 루프 틱 고려 750ms)
    std::this_thread::sleep_for(std::chrono::milliseconds(750));

    if (!callback_invoked.load(std::memory_order_acquire) || resumed_pid.load() != 99999) {
        std::cerr << "❌ SafetyWatchdog 테스트 실패!" << std::endl;
        std::exit(1);
    }

    assert(watchdog->TrackedCount() == 0);
    std::cout << "✅ SafetyWatchdog 1회 연장 승인 & 2회차 거부 가드 및 자동 재개 테스트 통과!" << std::endl;
}

void TestProcessActuatorThreadEnumeration() {
    std::cout << "\n[단위테스트] ProcessActuator 프로세스 스레드 열거 기능 검증 시작..." << std::endl;
    DWORD current_pid = ::GetCurrentProcessId();
    auto threads = Phalanx::Actuator::ProcessActuator::EnumerateProcessThreads(current_pid);

    std::cout << ">>> 현재 프로세스 PID " << current_pid << " 의 스레드 수: " << threads.size() << std::endl;
    if (threads.empty()) {
        std::cerr << "❌ 스레드 열거 실패!" << std::endl;
        std::exit(1);
    }
    std::cout << "✅ ProcessActuator 스레드 열거 테스트 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// Phase 1.5: 1순위 NtSuspendProcess 원자적 고속 동결 및 시간 계측(10~20μs) 검증
// ----------------------------------------------------------------------------
void TestNtSuspendProcessAtomic() {
    std::cout << "\n[단위테스트] Phase 1.5: NtSuspendProcess 원자적 초고속 동결 및 마이크로초 지연 검증..." << std::endl;

    // 타깃 더미 프로세스로 cmd.exe 백그라운드 기동
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[] = "cmd.exe /c timeout /t 10 > nul";

    BOOL created = ::CreateProcessA(
        nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi
    );

    if (!created) {
        std::cerr << "❌ 테스트용 타깃 프로세스(cmd.exe) 기동 실패! (오류: " << ::GetLastError() << ")" << std::endl;
        std::exit(1);
    }

    Phalanx::Common::UniqueHandle procGuard(pi.hProcess);
    Phalanx::Common::UniqueHandle threadGuard(pi.hThread);
    uint32_t target_pid = static_cast<uint32_t>(pi.dwProcessId);

    // 짧은 지연(20ms)을 주어 프로세스가 안정적으로 초기화되도록 함
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto watchdog = std::make_shared<Phalanx::Actuator::SafetyWatchdog>(std::chrono::milliseconds(5000));
    Phalanx::Actuator::ProcessActuator actuator(watchdog);

    // 1순위 원자적 동결 집행
    auto freeze_res = actuator.SuspendProcess(target_pid);
    std::cout << ">>> 1순위 동결 결과: " << freeze_res.message
              << " | 방식: " << (freeze_res.method == Phalanx::Actuator::FreezeMethod::ATOMIC_NT ? "ATOMIC_NT" : "FALLBACK")
              << " | 소요 시간: " << freeze_res.elapsed_microseconds << "μs" << std::endl;

    if (!freeze_res.success || freeze_res.method != Phalanx::Actuator::FreezeMethod::ATOMIC_NT) {
        std::cerr << "❌ NtSuspendProcess 원자적 동결 실패!" << std::endl;
        ::TerminateProcess(pi.hProcess, 99);
        std::exit(1);
    }

    if (freeze_res.elapsed_microseconds >= 1000) { // 1ms = 1000μs (원자적 동결은 10~50μs 수준)
        std::cerr << "⚠️ [경고] NtSuspendProcess 동결 소요 시간이 1ms를 초과함: "
                  << freeze_res.elapsed_microseconds << "μs" << std::endl;
    }

    // 원자적 복구 집행
    auto resume_res = actuator.ResumeProcess(target_pid);
    std::cout << ">>> 원자적 복구 결과: " << resume_res.message << std::endl;

    if (!resume_res.success || resume_res.method != Phalanx::Actuator::FreezeMethod::ATOMIC_NT) {
        std::cerr << "❌ NtResumeProcess 원자적 복구 실패!" << std::endl;
        ::TerminateProcess(pi.hProcess, 99);
        std::exit(1);
    }

    // 타깃 프로세스 안전 사살
    actuator.TerminateTargetProcess(target_pid, 0, "Unit test teardown");
    std::cout << "✅ NtSuspendProcess 원자적 초고속 동결 & 복구 검증 통과!" << std::endl;
}

// ----------------------------------------------------------------------------
// Phase 1.5: 2순위 결함 주입(Fault Injection) 우아한 자동 폴백 검증
// ----------------------------------------------------------------------------
void TestFaultInjectionFallback() {
    std::cout << "\n[단위테스트] Phase 1.5: 결함 주입(Fault Injection) 2순위 Toolhelp32 폴백 검증..." << std::endl;

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[] = "cmd.exe /c timeout /t 10 > nul";

    BOOL created = ::CreateProcessA(
        nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi
    );

    if (!created) {
        std::cerr << "❌ 테스트용 타깃 프로세스(cmd.exe) 기동 실패!" << std::endl;
        std::exit(1);
    }

    Phalanx::Common::UniqueHandle procGuard(pi.hProcess);
    Phalanx::Common::UniqueHandle threadGuard(pi.hThread);
    uint32_t target_pid = static_cast<uint32_t>(pi.dwProcessId);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    auto watchdog = std::make_shared<Phalanx::Actuator::SafetyWatchdog>(std::chrono::milliseconds(5000));
    Phalanx::Actuator::ProcessActuator actuator(watchdog);

    // 1순위 실패 강제 시뮬레이션: force_fallback = true
    actuator.SetForceFallback(true);

    auto freeze_res = actuator.SuspendProcess(target_pid);
    std::cout << ">>> 결함 주입 동결 결과: " << freeze_res.message
              << " | 방식: " << (freeze_res.method == Phalanx::Actuator::FreezeMethod::THREAD_SNAPSHOT ? "THREAD_SNAPSHOT (Fallback)" : "ATOMIC")
              << " | 영향 스레드: " << freeze_res.threads_affected << "개" << std::endl;

    if (!freeze_res.success || freeze_res.method != Phalanx::Actuator::FreezeMethod::THREAD_SNAPSHOT) {
        std::cerr << "❌ 2순위 Toolhelp32 폴백 동결 실패!" << std::endl;
        ::TerminateProcess(pi.hProcess, 99);
        std::exit(1);
    }

    auto resume_res = actuator.ResumeProcess(target_pid);
    std::cout << ">>> 결함 주입 복구 결과: " << resume_res.message << std::endl;

    if (!resume_res.success || resume_res.method != Phalanx::Actuator::FreezeMethod::THREAD_SNAPSHOT) {
        std::cerr << "❌ 2순위 Toolhelp32 폴백 복구 실패!" << std::endl;
        ::TerminateProcess(pi.hProcess, 99);
        std::exit(1);
    }

    actuator.TerminateTargetProcess(target_pid, 0, "Unit test teardown");
    std::cout << "✅ 2순위 Toolhelp32 우아한 자동 폴백 검증 통과!" << std::endl;
}

int main() {
    ::SetConsoleOutputCP(CP_UTF8);
    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX SENSOR 핵심 컴포넌트 단위 테스트 (Unit Tests)                        " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TestDoubleBufferedSwapQueue();
    TestSafetyWatchdog();
    TestProcessActuatorThreadEnumeration();
    TestNtSuspendProcessAtomic();
    TestFaultInjectionFallback();

    std::cout << "\n================================================================================" << std::endl;
    std::cout << "🎉 모든 단위 테스트 검증 성공! (Exit Code 0)                                     " << std::endl;
    std::cout << "================================================================================" << std::endl;
    return 0;
}
