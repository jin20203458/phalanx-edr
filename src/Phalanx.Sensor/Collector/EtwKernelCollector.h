#pragma once

#include <memory>
#include <string>
#include <functional>
#include "../Queue/DoubleBufferedSwapQueue.h"
#include "phalanx.pb.h"

namespace Phalanx::Collector {

using ProcessEventCallback = std::function<void(const phalanx::ProcessEvent&)>;

/**
 * @brief Real-time ETW Kernel Collector utilizing Microsoft krabs-etw.
 *
 * Subscribes to Microsoft-Windows-Kernel-Process manifest provider.
 * Extracts ProcessStart / ProcessStop events and pushes them into
 * the DoubleBufferedSwapQueue in microsecond-scale non-blocking callbacks.
 */
class EtwKernelCollector {
public:
    explicit EtwKernelCollector(std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue);
    ~EtwKernelCollector();

    EtwKernelCollector(const EtwKernelCollector&) = delete;
    EtwKernelCollector& operator=(const EtwKernelCollector&) = delete;

    /**
     * @brief Set an optional observer callback (e.g. for console logging or instant heuristics).
     */
    void SetProcessObserver(ProcessEventCallback callback);

    /**
     * @brief Starts the ETW trace session in a dedicated background worker.
     */
    bool Start();

    /**
     * @brief Stops the ETW trace session and joins the thread.
     */
    void Stop();

    [[nodiscard]] bool IsRunning() const noexcept;
    [[nodiscard]] size_t EventsCaptured() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Phalanx::Collector
