#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include "../Queue/DoubleBufferedSwapQueue.h"
#include "../Actuator/ProcessActuator.h"
#include "phalanx.pb.h"
#include "phalanx.grpc.pb.h"

namespace Phalanx::Ipc {

using CommandHandler = std::function<void(const phalanx::MitigationCommand&)>;

/**
 * @brief High-throughput bidirectional gRPC streaming client for Phalanx Telemetry.
 *
 * Implements asio-grpc C++20 coroutines:
 *  - Outbound loop: 10ms periodic timer flushes DoubleBufferedSwapQueue and writes TelemetryBatch.
 *  - Inbound loop: Reads MitigationCommands and routes them to ProcessActuator.
 *  - Auto-reconnect with exponential backoff on disconnect.
 */
class GrpcStreamClient {
public:
    GrpcStreamClient(std::string target_endpoint,
                     std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue,
                     std::shared_ptr<Actuator::ProcessActuator> actuator);
    ~GrpcStreamClient();

    GrpcStreamClient(const GrpcStreamClient&) = delete;
    GrpcStreamClient& operator=(const GrpcStreamClient&) = delete;

    void SetCustomCommandHandler(CommandHandler handler);

    /**
     * @brief Starts the background asio-grpc thread and connection loop.
     */
    bool Start();

    /**
     * @brief Stops the client and shuts down active streams.
     */
    void Stop();

    [[nodiscard]] bool IsConnected() const noexcept {
        return is_connected_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] size_t BatchesSent() const noexcept {
        return batches_sent_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] size_t EventsSent() const noexcept {
        return events_sent_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] size_t CommandsReceived() const noexcept {
        return commands_received_.load(std::memory_order_relaxed);
    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::atomic<bool> is_connected_{false};
    std::atomic<size_t> batches_sent_{0};
    std::atomic<size_t> events_sent_{0};
    std::atomic<size_t> commands_received_{0};
};

} // namespace Phalanx::Ipc
