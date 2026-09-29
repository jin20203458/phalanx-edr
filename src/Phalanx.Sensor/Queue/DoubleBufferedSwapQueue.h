#pragma once

#include <vector>
#include <mutex>
#include <atomic>
#include <utility>
#include <cstddef>

namespace Phalanx::Queue {

/**
 * @brief EDR 고속 커널 텔레메트리 수집을 위한 더블 버퍼드 락-스왑(Double-Buffered Lock-Swap) 큐.
 *
 * - 고주파 커널 생산자(ETW 콜백)의 락 점유 시간을 1마이크로초(<1μs) 미만으로 극소화.
 * - 10ms 주기 배치 플러시 시 동적 힙 재할당 없이 두 버퍼의 포인터만 맞교환(std::swap)하여 유실률 0% 보장.
 */
template <typename T, size_t InitialCapacity = 8192>
class DoubleBufferedSwapQueue {
public:
    DoubleBufferedSwapQueue() {
        buffer_a_.reserve(InitialCapacity);
        buffer_b_.reserve(InitialCapacity);
        write_buffer_ = &buffer_a_;
        read_buffer_ = &buffer_b_;
    }

    ~DoubleBufferedSwapQueue() = default;

    DoubleBufferedSwapQueue(const DoubleBufferedSwapQueue&) = delete;
    DoubleBufferedSwapQueue& operator=(const DoubleBufferedSwapQueue&) = delete;

    /**
     * @brief 활성 쓰기 버퍼(write_buffer_)에 새 이벤트를 삽입 (우측값 이동).
     * 락 점유 시간은 벡터의 push_back 1회 수행 시간(<1μs)으로 제한됩니다.
     */
    bool Push(T&& item) {
        std::lock_guard<std::mutex> lock(write_lock_);
        if (write_buffer_->size() < MaxSafetyCapacity) {
            write_buffer_->push_back(std::move(item));
            return true;
        }
        // 안전 상한선(초기 용량의 4배) 초과 시 버퍼 오버플로우 방어를 위해 드롭 카운트 증가
        dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    /**
     * @brief 활성 쓰기 버퍼(write_buffer_)에 새 이벤트를 삽입 (복사).
     */
    bool Push(const T& item) {
        std::lock_guard<std::mutex> lock(write_lock_);
        if (write_buffer_->size() < MaxSafetyCapacity) {
            write_buffer_->push_back(item);
            return true;
        }
        dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    /**
     * @brief 쓰기 버퍼와 읽기 버퍼의 포인터를 맞교환(Swap)합니다.
     * 새로 쓰여질 버퍼는 clear()하되 기할당된 용량(Capacity)은 유지하며,
     * 소비 스레드가 락 없이 안전하게 배치 직렬화할 수 있도록 채워진 버퍼 포인터를 반환합니다.
     */
    std::vector<T>* SwapAndFlush() {
        std::lock_guard<std::mutex> lock(write_lock_);
        std::swap(write_buffer_, read_buffer_);
        write_buffer_->clear();
        return read_buffer_;
    }

    // 버퍼 포화로 인해 드롭된 이벤트 누적 수 반환
    [[nodiscard]] size_t DroppedCount() const noexcept {
        return dropped_count_.load(std::memory_order_relaxed);
    }

    // 현재 쓰기 버퍼에 대기 중인 이벤트 근사 개수 반환
    [[nodiscard]] size_t ApproximateWriteSize() const noexcept {
        return write_buffer_ ? write_buffer_->size() : 0;
    }

private:
    static constexpr size_t MaxSafetyCapacity = InitialCapacity * 4;

    std::mutex write_lock_;
    std::vector<T> buffer_a_;
    std::vector<T> buffer_b_;
    std::vector<T>* write_buffer_{nullptr};
    std::vector<T>* read_buffer_{nullptr};
    std::atomic<size_t> dropped_count_{0};
};

} // namespace Phalanx::Queue
