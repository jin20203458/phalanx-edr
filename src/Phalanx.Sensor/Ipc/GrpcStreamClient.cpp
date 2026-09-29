#include "GrpcStreamClient.h"
#include <grpcpp/grpcpp.h>
#include <agrpc/asio_grpc.hpp>
#include <agrpc/client_rpc.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <iostream>
#include <mutex>

namespace Phalanx::Ipc {

using RPC = agrpc::ClientRPC<&phalanx::PhalanxService::Stub::PrepareAsyncStreamTelemetry>;

struct GrpcStreamClient::Impl {
    std::string target_endpoint;
    std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue;
    std::shared_ptr<Actuator::ProcessActuator> actuator;
    CommandHandler custom_command_handler;

    agrpc::GrpcContext grpc_context;
    std::atomic<bool> running{false};
    std::thread worker_thread;

    std::mutex rpc_lock;
    std::shared_ptr<RPC> active_rpc;

    Impl(std::string endpoint,
         std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> q,
         std::shared_ptr<Actuator::ProcessActuator> act)
        : target_endpoint(std::move(endpoint)),
          queue(std::move(q)),
          actuator(std::move(act)) {}
};

GrpcStreamClient::GrpcStreamClient(std::string target_endpoint,
                                   std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue,
                                   std::shared_ptr<Actuator::ProcessActuator> actuator)
    : impl_(std::make_unique<Impl>(std::move(target_endpoint), std::move(queue), std::move(actuator))) {
}

GrpcStreamClient::~GrpcStreamClient() {
    Stop();
}

void GrpcStreamClient::SetCustomCommandHandler(CommandHandler handler) {
    impl_->custom_command_handler = std::move(handler);
}

bool GrpcStreamClient::Start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return true;
    }
    impl_->running.store(true, std::memory_order_release);

    impl_->worker_thread = std::thread([this]() {
        // 비동기 통신 연결 및 재연결 제어 코루틴
        auto connection_coro = [this]() -> boost::asio::awaitable<void> {
            while (impl_->running.load(std::memory_order_relaxed)) {
                try {
                    auto channel = grpc::CreateChannel(impl_->target_endpoint, grpc::InsecureChannelCredentials());
                    auto stub = phalanx::PhalanxService::NewStub(channel);

                    auto rpc = std::make_shared<RPC>(impl_->grpc_context);

                    // 양방향 스트림 연결 시작
                    bool start_ok = co_await rpc->start(*stub, boost::asio::use_awaitable);

                    if (!start_ok) {
                        is_connected_.store(false, std::memory_order_release);
                        // 연결 실패 시 2초 대기 후 재시도
                        boost::asio::steady_timer retry_timer(impl_->grpc_context);
                        retry_timer.expires_after(std::chrono::seconds(2));
                        co_await retry_timer.async_wait(boost::asio::use_awaitable);
                        continue;
                    }

                    {
                        std::lock_guard<std::mutex> lk(impl_->rpc_lock);
                        impl_->active_rpc = rpc;
                    }

                    is_connected_.store(true, std::memory_order_release);
                    std::cout << "⚡ [gRPC] 텔레메트리 스트림 연결 성공: " << impl_->target_endpoint << std::endl;

                    std::atomic<bool> stream_active{true};

                    // [수신 코루틴] Core 대뇌에서 전달하는 방어 명령(MitigationCommand) 비동기 수신
                    auto read_coro = [this, rpc, &stream_active]() -> boost::asio::awaitable<void> {
                        try {
                            phalanx::MitigationCommand cmd;
                            while (impl_->running.load(std::memory_order_relaxed) && stream_active.load(std::memory_order_relaxed)) {
                                bool read_ok = co_await rpc->read(cmd, boost::asio::use_awaitable);
                                if (!read_ok) {
                                    stream_active.store(false, std::memory_order_release);
                                    break;
                                }

                                commands_received_.fetch_add(1, std::memory_order_relaxed);
                                std::cout << "🛡️ [gRPC 방어 명령 수신] 조치: " << cmd.action()
                                          << " | 대상 PID: " << cmd.target_pid()
                                          << " | 사유: " << cmd.reason() << std::endl;

                                if (impl_->custom_command_handler) {
                                    impl_->custom_command_handler(cmd);
                                }

                                if (impl_->actuator) {
                                    switch (cmd.action()) {
                                        case phalanx::MitigationCommand::ACTION_KILL:
                                            impl_->actuator->TerminateTargetProcess(cmd.target_pid(), 1, cmd.reason());
                                            break;
                                        case phalanx::MitigationCommand::ACTION_RESUME:
                                            impl_->actuator->ResumeProcess(cmd.target_pid());
                                            break;
                                        case phalanx::MitigationCommand::ACTION_BLOCK_IP:
                                            std::cout << "🌐 [Actuator] IP 차단 요청 수신: " << cmd.target_ip() << std::endl;
                                            break;
                                        case phalanx::MitigationCommand::ACTION_EXTEND_TIMEOUT:
                                            impl_->actuator->ExtendTimeout(cmd.target_pid());
                                            break;
                                        default:
                                            break;
                                    }
                                }
                            }
                        } catch (...) {
                            stream_active.store(false, std::memory_order_release);
                        }
                    };

                    boost::asio::co_spawn(impl_->grpc_context, read_coro(), boost::asio::detached);

                    // [송신 코루틴] 10ms 주기로 락-스왑 큐를 플러시하여 TelemetryBatch 전송
                    boost::asio::steady_timer flush_timer(impl_->grpc_context);
                    while (impl_->running.load(std::memory_order_relaxed) && stream_active.load(std::memory_order_relaxed)) {
                        flush_timer.expires_after(std::chrono::milliseconds(10));
                        co_await flush_timer.async_wait(boost::asio::use_awaitable);

                        if (impl_->queue) {
                            auto* events = impl_->queue->SwapAndFlush();
                            if (events && !events->empty()) {
                                phalanx::TelemetryBatch batch;
                                for (auto& ev : *events) {
                                    *batch.add_process_events() = std::move(ev);
                                }

                                bool write_ok = co_await rpc->write(batch, boost::asio::use_awaitable);
                                if (!write_ok) {
                                    stream_active.store(false, std::memory_order_release);
                                    break;
                                }

                                batches_sent_.fetch_add(1, std::memory_order_relaxed);
                                events_sent_.fetch_add(batch.process_events_size(), std::memory_order_relaxed);
                            }
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lk(impl_->rpc_lock);
                        impl_->active_rpc = nullptr;
                    }

                    try {
                        co_await rpc->writes_done(boost::asio::use_awaitable);
                        grpc::Status finish_status = co_await rpc->finish(boost::asio::use_awaitable);
                    } catch (...) {
                    }

                    is_connected_.store(false, std::memory_order_release);
                } catch (const std::exception& ex) {
                    std::cerr << "[gRPC 예외 발생] " << ex.what() << std::endl;
                    is_connected_.store(false, std::memory_order_release);
                }

                if (impl_->running.load(std::memory_order_relaxed)) {
                    boost::asio::steady_timer retry_timer(impl_->grpc_context);
                    retry_timer.expires_after(std::chrono::seconds(2));
                    co_await retry_timer.async_wait(boost::asio::use_awaitable);
                }
            }
        };

        boost::asio::co_spawn(impl_->grpc_context, connection_coro(), boost::asio::detached);
        impl_->grpc_context.run();
    });

    return true;
}

void GrpcStreamClient::Stop() {
    if (!impl_->running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lk(impl_->rpc_lock);
        if (impl_->active_rpc) {
            impl_->active_rpc->context().TryCancel();
        }
    }

    impl_->grpc_context.stop();

    if (impl_->worker_thread.joinable()) {
        impl_->worker_thread.join();
    }

    is_connected_.store(false, std::memory_order_release);
}

} // namespace Phalanx::Ipc
