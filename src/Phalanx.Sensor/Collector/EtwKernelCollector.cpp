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
            // Microsoft-Windows-Kernel-Process 프로바이더 GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
            static const krabs::guid KernelProcessGuid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}");
            krabs::provider<> provider(KernelProcessGuid);

            provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
                try {
                    krabs::schema schema(record, trace_context.schema_locator);
                    // 이벤트 ID 1: ProcessStart (프로세스 생성)
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

                        // 실시간 콘솔 출력 또는 휴리스틱 감시용 옵저버 통지
                        if (impl_->observer_callback) {
                            impl_->observer_callback(ev);
                        }

                        // 락-스왑 큐로 즉시 푸시 (수집 스레드 블로킹 방지)
                        if (impl_->queue) {
                            impl_->queue->Push(std::move(ev));
                        }
                    }
                } catch (...) {
                    // 비블로킹 원칙 준수: 손상된 이벤트 레코드는 무시하고 즉시 복귀
                }
            });

            impl_->trace = std::make_unique<krabs::user_trace>(L"PhalanxKernelProcessSession");
            impl_->trace->enable(provider);
            std::cout << "🚀 [ETW] Microsoft-Windows-Kernel-Process 트레이스 세션 구동 중..." << std::endl;
            impl_->trace->start();
            std::cout << "🛑 [ETW] 트레이스 세션 종료됨." << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "❌ [ETW 예외 발생] " << ex.what() << std::endl;
            impl_->running.store(false, std::memory_order_release);
        } catch (...) {
            std::cerr << "❌ [ETW 알 수 없는 예외 발생]" << std::endl;
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
