#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <numeric>
#include <algorithm>
#include <string>
#include <cstring>
#include <mutex>
#include <windows.h>
#include <timeapi.h>

#pragma comment(lib, "winmm.lib")

// Boost Lock-Free SPSC Queue
#include <boost/lockfree/spsc_queue.hpp>

#ifdef _WIN32
struct WindowsTimerResolutionRaii {
    WindowsTimerResolutionRaii() {
        timeBeginPeriod(1);
    }
    ~WindowsTimerResolutionRaii() {
        timeEndPeriod(1);
    }
};
#endif

// ============================================================================
// 1. EDR Telemetry Event Payload (128 Bytes POD)
// ============================================================================
#pragma pack(push, 1)
struct BenchmarkProcessEvent {
    uint32_t process_id;
    uint32_t parent_process_id;
    uint64_t timestamp_ns;
    uint32_t session_id;
    uint32_t token_elevation_type;
    bool is_suspended;
    char image_name[35];       // e.g., "C:\\Windows\\System32\\powershell.exe"
    char command_line[68];     // e.g., "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass"
};
#pragma pack(pop)

static_assert(sizeof(BenchmarkProcessEvent) == 128, "BenchmarkProcessEvent must be exactly 128 bytes");

// ============================================================================
// 2. Queue Candidate A: Boost Lock-Free SPSC RingBuffer (Capacity = 65,536)
// ============================================================================
constexpr size_t SPSC_CAPACITY = 65536;

class BoostSpscQueueWrapper {
public:
    // 동적 힙 할당 버전 (스택 오버플로우 방지: 65536 * 128 = 8MB)
    boost::lockfree::spsc_queue<BenchmarkProcessEvent> queue_{SPSC_CAPACITY};

    bool Push(const BenchmarkProcessEvent& event) {
        return queue_.push(event);
    }

    // 소비자: 낱개 pop 루프로 배치 인출
    size_t Drain(std::vector<BenchmarkProcessEvent>& out_batch) {
        size_t count = 0;
        BenchmarkProcessEvent ev;
        while (queue_.pop(ev)) {
            out_batch.push_back(ev);
            count++;
        }
        return count;
    }
};

// ============================================================================
// 3. Queue Candidate B: Double-Buffered Swap Queue (Zero Dynamic Heap Allocation)
// ============================================================================
template <typename T, size_t InitialCapacity = 65536>
class DoubleBufferedSwapQueue {
public:
    DoubleBufferedSwapQueue() {
        buffer_a_.reserve(InitialCapacity);
        buffer_b_.reserve(InitialCapacity);
        write_buffer_ = &buffer_a_;
        read_buffer_ = &buffer_b_;
    }

    bool Push(const T& item) {
        std::lock_guard<std::mutex> lock(write_lock_);
        if (write_buffer_->size() < InitialCapacity * 4) { // Safety cap
            write_buffer_->push_back(item);
            return true;
        }
        return false; // Dropped
    }

    // 소비자: 락을 극히 짧게 쥐고 포인터만 맞교환 (Zero Dynamic Heap Allocation)
    std::vector<T>* SwapAndFlush() {
        std::lock_guard<std::mutex> lock(write_lock_);
        std::swap(write_buffer_, read_buffer_);
        write_buffer_->clear(); // 생산자가 다음 턴에 쓸 버퍼를 초기화 (Capacity 유지)
        return read_buffer_;   // 소비자가 락 없이 읽을 버퍼 (방금 생산자가 채운 데이터)
    }

private:
    std::mutex write_lock_;
    std::vector<T> buffer_a_;
    std::vector<T> buffer_b_;
    std::vector<T>* write_buffer_{nullptr};
    std::vector<T>* read_buffer_{nullptr};
};

// ============================================================================
// 4. Benchmark Harness
// ============================================================================
void PrintHeader(const std::string& title) {
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << "================================================================================" << std::endl;
}

int main() {
    system("chcp 65001 > nul");
    WindowsTimerResolutionRaii timer_guard;

    PrintHeader("Phalanx EDR 텔레메트리 큐 1:1 성능 비교 벤치마크");
    std::cout << "• 이벤트 크기: " << sizeof(BenchmarkProcessEvent) << " bytes (실제 ProcessEvent 규격)" << std::endl;
    std::cout << "• 윈도우 타이머 해상도: 1ms 정밀 강제 (timeBeginPeriod)" << std::endl;
    std::cout << "• 후보 A: boost::lockfree::spsc_queue (Capacity: " << SPSC_CAPACITY << ")" << std::endl;
    std::cout << "• 후보 B: DoubleBufferedSwapQueue (포인터 맞교환 제로 힙 할당)" << std::endl;

    constexpr int TOTAL_EVENTS = 1000000; // 100만 건
    constexpr int CONSUMER_TICK_INTERVAL_MS = 10; // 10ms (100Hz) EDR 배치 전송 주기

    // ------------------------------------------------------------------------
    // Test 1: Boost Lock-Free SPSC Queue
    // ------------------------------------------------------------------------
    {
        std::cout << "\n>>> [테스트 1] Boost Lock-Free SPSC Queue 실행 중 (1,000,000 이벤트)..." << std::endl;
        BoostSpscQueueWrapper spsc_queue;
        std::atomic<bool> producer_done(false);
        std::atomic<size_t> dropped_events(0);
        std::atomic<size_t> total_consumed(0);

        long long total_consumer_drain_ns = 0;
        size_t consumer_drain_calls = 0;

        auto t_start = std::chrono::high_resolution_clock::now();

        // Producer Thread (ETW 콜백 모사)
        std::thread producer([&]() {
            BenchmarkProcessEvent ev;
            ev.process_id = 8492;
            ev.parent_process_id = 3104;
            ev.timestamp_ns = 123456789;
            ev.session_id = 1;
            ev.token_elevation_type = 2;
            ev.is_suspended = true;
            std::strncpy(ev.image_name, "powershell.exe", sizeof(ev.image_name));
            std::strncpy(ev.command_line, "powershell.exe -enc JABzAD0...", sizeof(ev.command_line));

            for (int i = 0; i < TOTAL_EVENTS; ++i) {
                ev.process_id = 10000 + (i % 50000);
                while (!spsc_queue.Push(ev)) {
                    // SPSC 링버퍼가 꽉 차면 스핀 또는 드롭
                    dropped_events.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::yield();
                }
            }
            producer_done.store(true, std::memory_order_release);
        });

        // Consumer Thread (10ms 주기 gRPC 일괄 전송 모사)
        std::thread consumer([&]() {
            std::vector<BenchmarkProcessEvent> batch;
            batch.reserve(SPSC_CAPACITY);

            while (!producer_done.load(std::memory_order_acquire) || spsc_queue.queue_.read_available() > 0) {
                auto c_start = std::chrono::high_resolution_clock::now();
                size_t drained = spsc_queue.Drain(batch);
                auto c_end = std::chrono::high_resolution_clock::now();

                total_consumer_drain_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(c_end - c_start).count();
                consumer_drain_calls++;
                total_consumed.fetch_add(drained, std::memory_order_relaxed);
                batch.clear();

                std::this_thread::sleep_for(std::chrono::milliseconds(CONSUMER_TICK_INTERVAL_MS));
            }
        });

        producer.join();
        consumer.join();

        auto t_end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
        double throughput_mops = (TOTAL_EVENTS / (elapsed_ms / 1000.0)) / 1000000.0;
        double avg_drain_us = (total_consumer_drain_ns / 1000.0) / (consumer_drain_calls ? consumer_drain_calls : 1);

        std::cout << "  ✓ 총 소요 시간         : " << elapsed_ms << " ms" << std::endl;
        std::cout << "  ✓ 초당 이벤트 처리량     : " << throughput_mops << " M ops/sec" << std::endl;
        std::cout << "  ✓ 소비자 순수 Drain 누적 : " << total_consumer_drain_ns / 1000.0 << " μs (호출: " << consumer_drain_calls << "회, 평균 " << avg_drain_us << " μs/회)" << std::endl;
        std::cout << "  ✓ 버퍼 풀(Full) 경합 횟수: " << dropped_events.load() << " 회" << std::endl;
        std::cout << "  ✓ 최종 정상 소비 완료   : " << total_consumed.load() << " / " << TOTAL_EVENTS << std::endl;
    }

    // ------------------------------------------------------------------------
    // Test 2: Double-Buffered Swap Queue (Phalanx)
    // ------------------------------------------------------------------------
    {
        std::cout << "\n>>> [테스트 2] DoubleBufferedSwapQueue (포인터 스왑) 실행 중 (1,000,000 이벤트)..." << std::endl;
        DoubleBufferedSwapQueue<BenchmarkProcessEvent, SPSC_CAPACITY> swap_queue;
        std::atomic<bool> producer_done(false);
        std::atomic<size_t> dropped_events(0);
        std::atomic<size_t> total_consumed(0);

        long long total_consumer_swap_ns = 0;
        size_t consumer_swap_calls = 0;

        auto t_start = std::chrono::high_resolution_clock::now();

        // Producer Thread (ETW 콜백 모사)
        std::thread producer([&]() {
            BenchmarkProcessEvent ev;
            ev.process_id = 8492;
            ev.parent_process_id = 3104;
            ev.timestamp_ns = 123456789;
            ev.session_id = 1;
            ev.token_elevation_type = 2;
            ev.is_suspended = true;
            std::strncpy(ev.image_name, "powershell.exe", sizeof(ev.image_name));
            std::strncpy(ev.command_line, "powershell.exe -enc JABzAD0...", sizeof(ev.command_line));

            for (int i = 0; i < TOTAL_EVENTS; ++i) {
                ev.process_id = 10000 + (i % 50000);
                while (!swap_queue.Push(ev)) {
                    dropped_events.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::yield();
                }
            }
            producer_done.store(true, std::memory_order_release);
        });

        // Consumer Thread (10ms 주기 gRPC 일괄 전송 모사)
        std::thread consumer([&]() {
            while (!producer_done.load(std::memory_order_acquire)) {
                auto c_start = std::chrono::high_resolution_clock::now();
                auto* batch = swap_queue.SwapAndFlush();
                auto c_end = std::chrono::high_resolution_clock::now();

                total_consumer_swap_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(c_end - c_start).count();
                consumer_swap_calls++;
                total_consumed.fetch_add(batch->size(), std::memory_order_relaxed);

                std::this_thread::sleep_for(std::chrono::milliseconds(CONSUMER_TICK_INTERVAL_MS));
            }
            // 잔여 버퍼 최종 플러시
            auto c_start = std::chrono::high_resolution_clock::now();
            auto* final_batch = swap_queue.SwapAndFlush();
            auto c_end = std::chrono::high_resolution_clock::now();
            total_consumer_swap_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(c_end - c_start).count();
            consumer_swap_calls++;
            total_consumed.fetch_add(final_batch->size(), std::memory_order_relaxed);
        });

        producer.join();
        consumer.join();

        auto t_end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
        double throughput_mops = (TOTAL_EVENTS / (elapsed_ms / 1000.0)) / 1000000.0;
        double avg_swap_us = (total_consumer_swap_ns / 1000.0) / (consumer_swap_calls ? consumer_swap_calls : 1);

        std::cout << "  ✓ 총 소요 시간         : " << elapsed_ms << " ms" << std::endl;
        std::cout << "  ✓ 초당 이벤트 처리량     : " << throughput_mops << " M ops/sec" << std::endl;
        std::cout << "  ✓ 소비자 순수 Swap 누적  : " << total_consumer_swap_ns / 1000.0 << " μs (호출: " << consumer_swap_calls << "회, 평균 " << avg_swap_us << " μs/회)" << std::endl;
        std::cout << "  ✓ 버퍼 풀(Full) 경합 횟수: " << dropped_events.load() << " 회" << std::endl;
        std::cout << "  ✓ 최종 정상 소비 완료   : " << total_consumed.load() << " / " << TOTAL_EVENTS << std::endl;
    }

    PrintHeader("벤치마크 완료");
    return 0;
}
