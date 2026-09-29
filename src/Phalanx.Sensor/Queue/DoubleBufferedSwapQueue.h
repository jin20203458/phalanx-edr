#pragma once

#include <vector>
#include <mutex>
#include <atomic>
#include <utility>
#include <cstddef>

namespace Phalanx::Queue {

/**
 * @brief Double-Buffered Lock-Swap Ingestion Queue for EDR Telemetry.
 *
 * Provides microsecond (<1μs) lock hold duration for high-frequency kernel producers (ETW callbacks)
 * and zero dynamic heap re-allocation during 10ms batch flushes by exchanging buffer pointers.
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
     * @brief Pushes an item into the active write buffer.
     * Lock duration is limited to a vector push_back (<1 microsecond).
     */
    bool Push(T&& item) {
        std::lock_guard<std::mutex> lock(write_lock_);
        if (write_buffer_->size() < MaxSafetyCapacity) {
            write_buffer_->push_back(std::move(item));
            return true;
        }
        dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

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
     * @brief Swaps write and read buffers.
     * Clears the newly active write buffer (retaining allocated capacity)
     * and returns the read buffer containing accumulated elements for lock-free batch consumption.
     */
    std::vector<T>* SwapAndFlush() {
        std::lock_guard<std::mutex> lock(write_lock_);
        std::swap(write_buffer_, read_buffer_);
        write_buffer_->clear();
        return read_buffer_;
    }

    [[nodiscard]] size_t DroppedCount() const noexcept {
        return dropped_count_.load(std::memory_order_relaxed);
    }

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
