#include "EtwKernelCollector.h"
#include "../Common/Win32Handles.h"
#include <krabs.hpp>
#include <iostream>
#include <thread>
#include <atomic>

namespace Phalanx::Collector {

struct EtwKernelCollector::Impl {
    std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue;
    ProcessEventCallback observer_callback;

    std::atomic<bool> running{false};
    std::atomic<size_t> events_captured{0};
    std::unique_ptr<krabs::user_trace> trace;
    std::thread worker_thread;

    explicit Impl(std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> q)
        : queue(std::move(q)) {}
};

EtwKernelCollector::EtwKernelCollector(std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue)
    : impl_(std::make_unique<Impl>(std::move(queue))) {
}

EtwKernelCollector::~EtwKernelCollector() {
    Stop();
}

void EtwKernelCollector::SetProcessObserver(ProcessEventCallback callback) {
    impl_->observer_callback = std::move(callback);
}

bool EtwKernelCollector::Start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return true;
    }
    impl_->running.store(true, std::memory_order_release);

    impl_->worker_thread = std::thread([this]() {
        try {
            // Microsoft-Windows-Kernel-Process GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
            static const krabs::guid KernelProcessGuid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}");
            krabs::provider<> provider(KernelProcessGuid);

            provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
                try {
                    krabs::schema schema(record, trace_context.schema_locator);
                    // Event ID 1: ProcessStart
                    if (schema.event_id() == 1) {
                        krabs::parser parser(schema);
                        phalanx::ProcessEvent ev;

                        uint32_t pid = 0;
                        if (parser.try_parse(L"ProcessID", pid)) {
                            ev.set_process_id(pid);
                        }
                        uint32_t ppid = 0;
                        if (parser.try_parse(L"ParentProcessID", ppid)) {
                            ev.set_parent_process_id(ppid);
                        }
                        std::wstring img_w;
                        if (parser.try_parse(L"ImageName", img_w) || parser.try_parse(L"ImageFileName", img_w)) {
                            ev.set_image_name(Common::Utf16ToUtf8(img_w));
                        }
                        std::wstring cmd_w;
                        if (parser.try_parse(L"CommandLine", cmd_w)) {
                            ev.set_command_line(Common::Utf16ToUtf8(cmd_w));
                        }
                        uint32_t session_id = 0;
                        if (parser.try_parse(L"SessionID", session_id)) {
                            ev.set_session_id(session_id);
                        }
                        uint32_t elevation = 0;
                        if (parser.try_parse(L"TokenElevationType", elevation)) {
                            ev.set_token_elevation_type(elevation);
                        }

                        uint64_t ts = static_cast<uint64_t>(record.EventHeader.TimeStamp.QuadPart);
                        ev.set_timestamp_ns(ts);
                        ev.set_is_suspended(false);

                        impl_->events_captured.fetch_add(1, std::memory_order_relaxed);

                        if (impl_->observer_callback) {
                            impl_->observer_callback(ev);
                        }

                        if (impl_->queue) {
                            impl_->queue->Push(std::move(ev));
                        }
                    }
                } catch (...) {
                    // Non-blocking, drop malformed record
                }
            });

            impl_->trace = std::make_unique<krabs::user_trace>(L"PhalanxKernelProcessSession");
            impl_->trace->enable(provider);
            std::cout << "🚀 [ETW] Starting Microsoft-Windows-Kernel-Process trace session..." << std::endl;
            impl_->trace->start();
            std::cout << "🛑 [ETW] Trace session ended." << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "❌ [ETW Exception] " << ex.what() << std::endl;
            impl_->running.store(false, std::memory_order_release);
        } catch (...) {
            std::cerr << "❌ [ETW Unknown Exception]" << std::endl;
            impl_->running.store(false, std::memory_order_release);
        }
    });

    return true;
}

void EtwKernelCollector::Stop() {
    if (!impl_->running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    if (impl_->trace) {
        try {
            impl_->trace->stop();
        } catch (...) {
        }
    }

    if (impl_->worker_thread.joinable()) {
        impl_->worker_thread.join();
    }
}

bool EtwKernelCollector::IsRunning() const noexcept {
    return impl_->running.load(std::memory_order_relaxed);
}

size_t EtwKernelCollector::EventsCaptured() const noexcept {
    return impl_->events_captured.load(std::memory_order_relaxed);
}

} // namespace Phalanx::Collector
