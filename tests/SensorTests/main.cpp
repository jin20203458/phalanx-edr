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

    // 타임아웃 만료 대기
    std::this_thread::sleep_for(std::chrono::milliseconds(450));

    if (!callback_invoked.load(std::memory_order_acquire) || resumed_pid.load() != 99999) {
        std::cerr << "❌ SafetyWatchdog 테스트 실패!" << std::endl;
        std::exit(1);
    }

    assert(watchdog->TrackedCount() == 0);
    std::cout << "✅ SafetyWatchdog 자동 재개 테스트 통과!" << std::endl;
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

int main() {
    ::SetConsoleOutputCP(CP_UTF8);
    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX SENSOR 핵심 컴포넌트 단위 테스트 (Unit Tests)                        " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TestDoubleBufferedSwapQueue();
    TestSafetyWatchdog();
    TestProcessActuatorThreadEnumeration();

    std::cout << "\n================================================================================" << std::endl;
    std::cout << "🎉 모든 단위 테스트 검증 성공! (Exit Code 0)                                     " << std::endl;
    std::cout << "================================================================================" << std::endl;
    return 0;
}
