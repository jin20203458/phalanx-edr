#include "EtwKernelCollector.h"
#include "../Common/Win32Handles.h"
#include <krabs.hpp>
#include <iostream>
#include <thread>
#include <atomic>

namespace Phalanx::Collector {

struct EtwKernelCollector::Impl {
    std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue;
    std::shared_ptr<Process::ProcessTree> tree;
    std::shared_ptr<Rules::LocalRuleEngine> rule_engine;
    ProcessEventCallback observer_callback;

    std::atomic<bool> running{false};
    std::atomic<size_t> events_captured{0};
    std::unique_ptr<krabs::user_trace> trace;
    std::thread worker_thread;

    explicit Impl(std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> q,
                  std::shared_ptr<Process::ProcessTree> t,
                  std::shared_ptr<Rules::LocalRuleEngine> r)
        : queue(std::move(q)), tree(std::move(t)), rule_engine(std::move(r)) {}
};

EtwKernelCollector::EtwKernelCollector(
    std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue,
    std::shared_ptr<Process::ProcessTree> tree,
    std::shared_ptr<Rules::LocalRuleEngine> rule_engine)
    : impl_(std::make_unique<Impl>(std::move(queue), std::move(tree), std::move(rule_engine))) {
}

EtwKernelCollector::~EtwKernelCollector() {
    Stop();
}

void EtwKernelCollector::SetProcessTree(std::shared_ptr<Process::ProcessTree> tree) {
    impl_->tree = std::move(tree);
}

void EtwKernelCollector::SetRuleEngine(std::shared_ptr<Rules::LocalRuleEngine> rule_engine) {
    impl_->rule_engine = std::move(rule_engine);
}

void EtwKernelCollector::SetProcessObserver(ProcessEventCallback callback) {
    impl_->observer_callback = std::move(callback);
}

bool EtwKernelCollector::Start() {
    // 1. CAS 연산으로 오직 하나의 스레드만 false -> true 전이에 성공하도록 보장 (Check-Then-Act TOCTOU 방지)
    bool expected = false;
    if (!impl_->running.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return true; // 이미 가동 중이면 즉시 성공 반환
    }

    // 2. 스레드 생성 예외 안전성 확보 (OS 자원 부족 등으로 std::system_error 발생 시 원자적 롤백)
    try {
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
                            std::wstring image_name;
                            if (parser.try_parse(L"ImageName", image_name)) {
                                ev.set_image_name(Common::Utf16ToUtf8(image_name));
                            }
                            std::wstring cmd_line;
                            if (parser.try_parse(L"CommandLine", cmd_line)) {
                                ev.set_command_line(Common::Utf16ToUtf8(cmd_line));
                            }
                            uint32_t session_id = 0;
                            if (parser.try_parse(L"SessionID", session_id)) {
                                ev.set_session_id(session_id);
                            }
                            uint32_t token_elevation = 0;
                            if (parser.try_parse(L"TokenElevationType", token_elevation)) {
                                ev.set_token_elevation_type(token_elevation);
                            }

                            uint64_t ts = static_cast<uint64_t>(record.EventHeader.TimeStamp.QuadPart);
                            ev.set_timestamp_ns(ts);

                            // 1. C++ 인메모리 프로세스 트리(DAG) 갱신
                            if (impl_->tree) {
                                impl_->tree->OnProcessStart(ev);
                            }

                            // 2. 100μs 로컬 규칙 엔진 평가 및 액추에이터 집행 (사살/동결/통과)
                            if (impl_->rule_engine && impl_->tree) {
                                impl_->rule_engine->EvaluateAndAct(ev, *impl_->tree);
                            } else {
                                ev.set_is_suspended(false);
                                ev.set_is_terminated(false);
                            }

                            impl_->events_captured.fetch_add(1, std::memory_order_relaxed);

                            // 실시간 콘솔 출력 또는 휴리스틱 감시용 옵저버 통지
                            if (impl_->observer_callback) {
                                impl_->observer_callback(ev);
                            }

                            // 락-스왑 큐로 즉시 푸시 (수집 스레드 블로킹 방지)
                            if (impl_->queue) {
                                impl_->queue->Push(std::move(ev));
                            }
                        } else if (schema.event_id() == 2) {
                            // 이벤트 ID 2: ProcessStop (프로세스 종료)
                            krabs::parser parser(schema);
                            uint32_t pid = 0;
                            if (parser.try_parse(L"ProcessID", pid)) {
                                if (impl_->tree) {
                                    uint64_t ts = static_cast<uint64_t>(record.EventHeader.TimeStamp.QuadPart);
                                    impl_->tree->OnProcessStop(pid, ts);
                                }
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
    } catch (...) {
        impl_->running.store(false, std::memory_order_release);
        return false;
    }

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
